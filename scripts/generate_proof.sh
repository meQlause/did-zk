#!/usr/bin/env bash
# =============================================================================
# generate_proof.sh
# Generates a Groth16 ZK proof for a single credential rule.
#
# Usage:
#   ./scripts/generate_proof.sh <circuit_name> <inputs_json_file>
#
# Example:
#   ./scripts/generate_proof.sh number_gt inputs/age_gt_18.json
#
# Or pipe inline JSON:
#   echo '{"value":"25","key":"...","typ":"2","fieldHash":"...","credentialRoot":"...","threshold":"18"}' \
#     | ./scripts/generate_proof.sh number_gt -
#
# Outputs:
#   proofs/<circuit>_<timestamp>/
#     ├── witness.wtns       — witness binary
#     ├── proof.json         — Groth16 proof
#     ├── public.json        — public signals
#     └── verify_result.txt  — verification output
# =============================================================================

set -e

CIRCUIT_NAME="${1:-}"
INPUTS_FILE="${2:-}"
BUILD_DIR="build"
PROOFS_DIR="proofs"

# ── Colors ────────────────────────────────────────────────────────────────────
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[proof]${RESET} $*"; }
ok()   { echo -e "${GREEN}[  ok ]${RESET} $*"; }
err()  { echo -e "${RED}[error]${RESET} $*"; exit 1; }

# ── Usage ─────────────────────────────────────────────────────────────────────
if [ -z "$CIRCUIT_NAME" ] || [ -z "$INPUTS_FILE" ]; then
  echo ""
  echo -e "${BOLD}Usage:${RESET}  ./scripts/generate_proof.sh <circuit_name> <inputs.json>"
  echo ""
  echo "  Available circuits:"
  echo "    number_gt          — Number > threshold"
  echo "    number_range       — Number in [min, max]"
  echo "    number_eq          — Number = expected"
  echo "    date_range         — Date in [after, before]"
  echo "    text_hash_eq       — Text hash equals expected"
  echo "    attachment_hash_eq — Attachment doc hash equals expected"
  echo ""
  echo "  Example inputs JSON (number_gt):"
  echo '    {'
  echo '      "value":          "25",'
  echo '      "key":            "123456789",'
  echo '      "typ":            "2",'
  echo '      "fieldHash":      "987654321",'
  echo '      "credentialRoot": "111222333",'
  echo '      "threshold":      "18"'
  echo '    }'
  echo ""
  exit 0
fi

# ── Validate circuit exists ───────────────────────────────────────────────────
CIRCUIT_DIR="$BUILD_DIR/$CIRCUIT_NAME"
WASM="$CIRCUIT_DIR/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm"
ZKEY="$CIRCUIT_DIR/${CIRCUIT_NAME}.zkey"
VKEY="$CIRCUIT_DIR/${CIRCUIT_NAME}_vkey.json"

[ -d "$CIRCUIT_DIR" ] || err "Circuit build not found: $CIRCUIT_DIR — run trusted_setup.sh first"
[ -f "$WASM" ]        || err "WASM not found: $WASM"
[ -f "$ZKEY" ]        || err "zkey not found: $ZKEY"
[ -f "$VKEY" ]        || err "vkey not found: $VKEY"

# ── Resolve inputs ────────────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_DIR="$PROOFS_DIR/${CIRCUIT_NAME}_${TIMESTAMP}"
mkdir -p "$OUT_DIR"

INPUTS_TMP="$OUT_DIR/inputs.json"

if [ "$INPUTS_FILE" = "-" ]; then
  log "Reading inputs from stdin..."
  cat > "$INPUTS_TMP"
else
  [ -f "$INPUTS_FILE" ] || err "Inputs file not found: $INPUTS_FILE"
  cp "$INPUTS_FILE" "$INPUTS_TMP"
fi

log "Inputs:"
cat "$INPUTS_TMP" | python3 -m json.tool 2>/dev/null || cat "$INPUTS_TMP"
echo ""

echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Generating proof: $CIRCUIT_NAME${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}\n"

# ── Step 1: Compute witness ───────────────────────────────────────────────────
WITNESS="$OUT_DIR/witness.wtns"
log "Computing witness..."
snarkjs wtns calculate "$WASM" "$INPUTS_TMP" "$WITNESS"
ok "Witness → $WITNESS"

# ── Step 2: Generate Groth16 proof ───────────────────────────────────────────
PROOF="$OUT_DIR/proof.json"
PUBLIC="$OUT_DIR/public.json"
log "Generating Groth16 proof..."
snarkjs groth16 prove "$ZKEY" "$WITNESS" "$PROOF" "$PUBLIC"
ok "Proof → $PROOF"
ok "Public signals → $PUBLIC"

# ── Step 3: Verify proof ──────────────────────────────────────────────────────
VERIFY_OUT="$OUT_DIR/verify_result.txt"
log "Verifying proof..."
snarkjs groth16 verify "$VKEY" "$PUBLIC" "$PROOF" 2>&1 | tee "$VERIFY_OUT"

if grep -q "OK" "$VERIFY_OUT" 2>/dev/null || snarkjs groth16 verify "$VKEY" "$PUBLIC" "$PROOF" 2>&1 | grep -q "true"; then
  ok "Proof is VALID ✓"
  RESULT="VALID"
else
  echo -e "${RED}[error]${RESET} Proof verification FAILED"
  RESULT="INVALID"
fi

# ── Step 4: Print summary ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Summary${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""
echo "  Circuit:        $CIRCUIT_NAME"
echo "  Result:         $RESULT"
echo "  Output dir:     $OUT_DIR"
echo ""
echo "  Files:"
echo "    $WITNESS"
echo "    $PROOF"
echo "    $PUBLIC"
echo "    $VERIFY_OUT"
echo ""
echo "  Public signals:"
cat "$PUBLIC" | python3 -m json.tool 2>/dev/null || cat "$PUBLIC"
echo ""

# ── Optionally export a proof bundle for the verifier page ───────────────────
BUNDLE="$OUT_DIR/proof_bundle.json"
log "Writing proof bundle for verifier page → $BUNDLE"
python3 - <<PYEOF
import json, sys, datetime

try:
  with open("$INPUTS_TMP") as f:
    inputs = json.load(f)
  with open("$PROOF") as f:
    proof = json.load(f)
  with open("$PUBLIC") as f:
    public_signals = json.load(f)

  bundle = {
    "version": "1.0",
    "credentialRoot": inputs.get("credentialRoot", ""),
    "generatedAt": datetime.datetime.utcnow().isoformat() + "Z",
    "proofs": [{
      "rule": {
        "key":     inputs.get("_key_label", "$CIRCUIT_NAME"),
        "op":      "$CIRCUIT_NAME".replace("_", " ").split()[0] if "_" in "$CIRCUIT_NAME" else "$CIRCUIT_NAME",
        "val":     inputs.get("threshold", inputs.get("expected", "")),
        "min":     inputs.get("minVal", ""),
        "max":     inputs.get("maxVal", ""),
        "docHash": inputs.get("expectedDocHash", ""),
      },
      "field": {
        "key":      inputs.get("_key_label", "field"),
        "type":     int(inputs.get("typ", 0)),
        "typeName": ["Text","Email","Number","Date","Attachment File","Long Text"][int(inputs.get("typ",0))],
      },
      "circuit":       "$CIRCUIT_NAME.circom",
      "valid":         True,
      "witnessInputs": inputs,
      "proof":         proof,
      "publicSignals": public_signals,
    }]
  }

  with open("$BUNDLE", "w") as f:
    json.dump(bundle, f, indent=2)

  print(f"  Bundle written → $BUNDLE")
except Exception as e:
  print(f"  Could not write bundle: {e}", file=sys.stderr)
PYEOF

echo ""
echo -e "  Open ${CYAN}verifier.html${RESET} and load ${CYAN}$BUNDLE${RESET} to verify in the UI."
echo ""
