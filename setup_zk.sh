#!/bin/bash
# setup_zk.sh — ZK-Identity full pipeline (all 6 credential types)

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────
CircuitName="selective_disclosure"
CircuitsDir="circuits"
BuildDir="build_zk"
PtauSize=14   # 2^14 = 16384 constraints
InputsDir="zk_inputs"

# ─────────────────────────────────────────────────────────────────────────────
# Colours
# ─────────────────────────────────────────────────────────────────────────────
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✔ $*${NC}"; }
info() { echo -e "${CYAN}$*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${NC}"; }
fail() { echo -e "${RED}  ✘ $*${NC}"; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# Derived paths (single source of truth — change CircuitName/BuildDir above)
# ─────────────────────────────────────────────────────────────────────────────
PTAU_0="$BuildDir/pot${PtauSize}_0000.ptau"
PTAU_1="$BuildDir/pot${PtauSize}_0001.ptau"
PTAU_FINAL="$BuildDir/pot${PtauSize}_final.ptau"
R1CS="$BuildDir/${CircuitName}.r1cs"
WASM="$BuildDir/${CircuitName}_js/${CircuitName}.wasm"
ZKEY_0="$BuildDir/${CircuitName}_0000.zkey"
ZKEY_FINAL="$BuildDir/${CircuitName}_final.zkey"
VKEY="$BuildDir/verification_key.json"

mkdir -p "$BuildDir"

# ─────────────────────────────────────────────────────────────────────────────
# 1. Powers of Tau — Phase 1
# ─────────────────────────────────────────────────────────────────────────────
info "\n${BOLD}━━━ 1. Powers of Tau Phase 1 ━━━${NC}"

if [ ! -f "$PTAU_FINAL" ]; then
  echo "  Generating Powers of Tau (size=$PtauSize)..."

  npx snarkjs powersoftau new bn128 $PtauSize "$PTAU_0" -v

  npx snarkjs powersoftau contribute "$PTAU_0" "$PTAU_1" \
    --name="First contribution" -v \
    -e="$(head -c 10 /dev/urandom | base64)"

  npx snarkjs powersoftau prepare phase2 "$PTAU_1" "$PTAU_FINAL" -v

  ok "ptau finalised → $PTAU_FINAL"
else
  ok "Cached: $PTAU_FINAL"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. Compile Circuit
# ─────────────────────────────────────────────────────────────────────────────
info "\n${BOLD}━━━ 2. Compile Circuit ━━━${NC}"
echo "  Compiling ${CircuitsDir}/${CircuitName}.circom..."

circom "${CircuitsDir}/${CircuitName}.circom" \
  --r1cs --wasm --sym \
  -l ./node_modules \
  -o "$BuildDir"

ok "r1cs → $R1CS"
ok "wasm → $WASM"

# Print constraint count
npx snarkjs r1cs info "$R1CS" 2>/dev/null | grep -E "Constraints|Wires" | sed 's/^/  /' || true

# ─────────────────────────────────────────────────────────────────────────────
# 3. Groth16 Trusted Setup — Phase 2
# ─────────────────────────────────────────────────────────────────────────────
info "\n${BOLD}━━━ 3. Groth16 Trusted Setup (Phase 2) ━━━${NC}"

if [ ! -f "$ZKEY_FINAL" ]; then
  echo "  Generating zkey..."
  npx snarkjs groth16 setup "$R1CS" "$PTAU_FINAL" "$ZKEY_0"

  echo "  Contributing randomness..."
  npx snarkjs zkey contribute "$ZKEY_0" "$ZKEY_FINAL" \
    --name="1st Contributor Name" -v \
    -e="$(head -c 10 /dev/urandom | base64)"

  ok "zkey → $ZKEY_FINAL"
else
  ok "Cached: $ZKEY_FINAL"
fi

npx snarkjs zkey export verificationkey "$ZKEY_FINAL" "$VKEY"
ok "Verification key → $VKEY"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Build complete
# ─────────────────────────────────────────────────────────────────────────────
info "\n${GREEN}${BOLD}━━━ 4. Build Complete ━━━${NC}"
echo "  BuildDir         : $BuildDir"
echo "  Verification key : $VKEY"
echo "  WASM             : $WASM"
echo "  Final zkey       : $ZKEY_FINAL"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Prove & verify — all credential types via proof_manifest.json
# ─────────────────────────────────────────────────────────────────────────────
info "\n${BOLD}━━━ 5. Proving All Credential Types ━━━${NC}"

if [ ! -f "$InputsDir/proof_manifest.json" ]; then
  warn "$InputsDir/proof_manifest.json not found — run 'npm run demo' first to generate inputs"
  echo ""
  echo "  Falling back to legacy input files (input_age.json / input_email.json in $InputsDir)..."

  # ── Legacy fallback (backward-compatible with old demo) ───────────────────
  for LEGACY in age email; do
    INPUT="$InputsDir/input_${LEGACY}.json"
    if [ -f "$INPUT" ]; then
      PROOF="$BuildDir/${LEGACY}_proof.json"
      PUBLIC="$BuildDir/${LEGACY}_public.json"

      echo -e "\n  ── ${LEGACY} (legacy) ──"
      echo -n "     Proving... "
      npx snarkjs groth16 fullProve "$INPUT" "$WASM" "$ZKEY_FINAL" "$PROOF" "$PUBLIC"
      echo -e "${GREEN}done${NC}"

      echo -n "     Verifying... "
      if npx snarkjs groth16 verify "$VKEY" "$PUBLIC" "$PROOF" 2>&1 | grep -q "OK"; then
        echo -e "${GREEN}VALID ✔${NC}"
      else
        echo -e "${RED}INVALID ✘${NC}"
      fi
    fi
  done

  exit 0
fi

# ── Read manifest entries: "inputFile|label|type" ─────────────────────────
ENTRIES=$(node -e "
  const m = JSON.parse(require('fs').readFileSync('${InputsDir}/proof_manifest.json','utf8'));
  m.forEach(e => console.log(e.inputFile + '|' + e.label + '|' + e.type));
")

# ── Per-type labels for public signals ────────────────────────────────────
SIG_LABELS=("key" "credentialRoot" "walletAddress" "threshold" "expectedValueHash")

PASS=0
FAIL=0
declare -A RESULTS

while IFS='|' read -r INPUT_FILE LABEL TYPE_ID; do
  echo ""
  info "  ── ${BOLD}${LABEL}${NC}${CYAN} (type=${TYPE_ID}) ──${NC}"

  # Derive slug from input filename: "zk_inputs/input_email.json" → "email"
  SLUG=$(basename "$INPUT_FILE")
  SLUG="${SLUG#input_}"
  SLUG="${SLUG%.json}"
  PROOF_FILE="$BuildDir/proof_${SLUG}.json"
  PUBLIC_FILE="$BuildDir/public_${SLUG}.json"

  # ── 5a. Input file check ─────────────────────────────────────────────────
  if [ ! -f "$INPUT_FILE" ]; then
    warn "Missing: $INPUT_FILE — skipping"
    RESULTS["$LABEL"]="FAIL: input missing"
    ((FAIL++)) || true
    continue
  fi

  # ── 5b. Generate proof ───────────────────────────────────────────────────
  echo -n "     Proving...   "
  if npx snarkjs groth16 fullProve \
      "$INPUT_FILE" "$WASM" "$ZKEY_FINAL" \
      "$PROOF_FILE" "$PUBLIC_FILE" 2>/tmp/zk_err; then
    echo -e "${GREEN}done${NC}"
  else
    echo -e "${RED}FAILED${NC}"
    sed 's/^/     /' /tmp/zk_err
    RESULTS["$LABEL"]="FAIL: proof error"
    ((FAIL++)) || true
    continue
  fi

  # ── 5c. Verify proof ─────────────────────────────────────────────────────
  echo -n "     Verifying... "
  VERIFY_OUT=$(npx snarkjs groth16 verify "$VKEY" "$PUBLIC_FILE" "$PROOF_FILE" 2>&1)
  if echo "$VERIFY_OUT" | grep -q "OK"; then
    echo -e "${GREEN}VALID ✔${NC}"
    RESULTS["$LABEL"]="PASS"
    ((PASS++)) || true
  else
    echo -e "${RED}INVALID ✘${NC}"
    echo "$VERIFY_OUT" | sed 's/^/     /'
    RESULTS["$LABEL"]="FAIL: verification rejected"
    ((FAIL++)) || true
  fi

  # ── 5d. Print public signals ─────────────────────────────────────────────
  echo "     Public signals:"
  node -e "
    const sigs  = JSON.parse(require('fs').readFileSync('${PUBLIC_FILE}','utf8'));
    const lbls  = ['key','credentialRoot','walletAddress','threshold','expectedValueHash'];
    sigs.forEach((v,i) => {
      const short = v.length > 24 ? v.slice(0,24)+'...' : v;
      const label = lbls[i] || 'unknown';
      console.log('       ['+i+'] '+label.padEnd(20)+' = '+short);
    });
  "

done <<< "$ENTRIES"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Results summary
# ─────────────────────────────────────────────────────────────────────────────
info "\n${BOLD}━━━ 6. Results Summary ━━━${NC}"
printf "  %-26s %s\n" "Credential Type" "Result"
printf "  %-26s %s\n" "──────────────────────────" "──────"

for LABEL in "${!RESULTS[@]}"; do
  STATUS="${RESULTS[$LABEL]}"
  if [ "$STATUS" = "PASS" ]; then
    printf "  %-26s ${GREEN}%s${NC}\n" "$LABEL" "$STATUS"
  else
    printf "  %-26s ${RED}%s${NC}\n" "$LABEL" "$STATUS"
  fi
done

echo ""
echo -e "  Total: ${GREEN}${BOLD}${PASS} passed${NC}  ${RED}${BOLD}${FAIL} failed${NC}"
echo ""

[ "$FAIL" -eq 0 ] && ok "All proofs valid." || fail "${FAIL} proof(s) failed."