#!/usr/bin/env bash
# =============================================================================
# trusted_setup.sh
# Generates Powers of Tau and per-circuit zkKeys for all ZK credential circuits
#
# Prerequisites:
#   npm install -g snarkjs
#   npm install -g circom   (or install circom via cargo)
#
# Usage:
#   chmod +x scripts/trusted_setup.sh
#   ./scripts/trusted_setup.sh
#
# Outputs (all under build/):
#   build/pot/          — Powers of Tau files
#   build/<circuit>/    — r1cs, wasm, sym, zkey, vkey per circuit
# =============================================================================

set -e

# ── Config ────────────────────────────────────────────────────────────────────
CIRCUITS_DIR="../circuits"
BUILD_DIR="build"
POT_DIR="$BUILD_DIR/pot"
POT_POWER=14              # 2^14 = 16384 constraints max; increase if needed
CIRCOM_LIB="node_modules" # circomlib location after: npm install circomlib

# Circuit list: filename (without .circom) → main component name
declare -A CIRCUITS=(
  [number_gt]="NumberGTValidator"
  [number_range]="NumberRangeValidator"
  [number_eq]="NumberEQValidator"
  [date_range]="DateRangeValidator"
  [text_hash_eq]="TextHashEQValidator"
  [attachment_hash_eq]="AttachmentFileValidator"
)

# ── Colors ────────────────────────────────────────────────────────────────────
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[setup]${RESET} $*"; }
ok()   { echo -e "${GREEN}[  ok ]${RESET} $*"; }
warn() { echo -e "${YELLOW}[ warn]${RESET} $*"; }
err()  { echo -e "${RED}[error]${RESET} $*"; exit 1; }

# ── Dependency checks ─────────────────────────────────────────────────────────
command -v snarkjs >/dev/null 2>&1 || err "snarkjs not found. Run: npm install -g snarkjs"
command -v circom  >/dev/null 2>&1 || err "circom not found. Install from https://docs.circom.io/getting-started/installation/"

echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  ZK Credential — Trusted Setup${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}\n"

# ── Create directories ────────────────────────────────────────────────────────
mkdir -p "$POT_DIR"
for name in "${!CIRCUITS[@]}"; do
  mkdir -p "$BUILD_DIR/$name"
done

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Powers of Tau (universal, not circuit-specific)
# ─────────────────────────────────────────────────────────────────────────────
log "Phase 1: Powers of Tau (power=$POT_POWER)"

POT_0="$POT_DIR/pot${POT_POWER}_0000.ptau"
POT_1="$POT_DIR/pot${POT_POWER}_0001.ptau"
POT_FINAL="$POT_DIR/pot${POT_POWER}_final.ptau"

if [ -f "$POT_FINAL" ]; then
  warn "pot_final already exists — skipping Phase 1. Delete $POT_FINAL to regenerate."
else
  log "  new ptau..."
  snarkjs powersoftau new bn128 $POT_POWER "$POT_0" -v

  log "  contribute (random entropy)..."
  snarkjs powersoftau contribute "$POT_0" "$POT_1" \
    --name="Initial contribution" -v -e="$(openssl rand -hex 32)"

  log "  prepare phase2..."
  snarkjs powersoftau prepare phase2 "$POT_1" "$POT_FINAL" -v

  ok "Powers of Tau ready → $POT_FINAL"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Per-circuit setup
# ─────────────────────────────────────────────────────────────────────────────
log "Phase 2: Per-circuit compilation + zkey generation"
echo ""

for NAME in "${!CIRCUITS[@]}"; do
  COMP="${CIRCUITS[$NAME]}"
  SRC="$CIRCUITS_DIR/${NAME}.circom"
  OUT="$BUILD_DIR/$NAME"

  echo -e "${BOLD}── Circuit: $NAME ($COMP) ──${RESET}"

  [ -f "$SRC" ] || { warn "  $SRC not found — skipping"; echo ""; continue; }

  # 2a. Compile circuit → r1cs + wasm + sym
  log "  compiling $SRC..."
  circom "$SRC" \
    --r1cs \
    --wasm \
    --sym \
    -o "$OUT" \
    -l "$CIRCOM_LIB"
  ok "  compiled → $OUT/${NAME}.r1cs"

  # 2b. Groth16 setup (circuit-specific zkey, phase 1)
  ZKEY_0="$OUT/${NAME}_0000.zkey"
  log "  groth16 setup..."
  snarkjs groth16 setup \
    "$OUT/${NAME}.r1cs" \
    "$POT_FINAL" \
    "$ZKEY_0"
  ok "  initial zkey → $ZKEY_0"

  # 2c. Contribute to phase 2 (at least one contribution required)
  ZKEY_FINAL="$OUT/${NAME}.zkey"
  log "  phase 2 contribution..."
  snarkjs zkey contribute \
    "$ZKEY_0" "$ZKEY_FINAL" \
    --name="Contribution for $NAME" \
    -e="$(openssl rand -hex 32)"
  ok "  final zkey → $ZKEY_FINAL"

  # 2d. Export verification key (used by verifier)
  VKEY="$OUT/${NAME}_vkey.json"
  log "  exporting vkey..."
  snarkjs zkey export verificationkey "$ZKEY_FINAL" "$VKEY"
  ok "  vkey → $VKEY"

  # 2e. Print circuit info
  log "  circuit info:"
  snarkjs r1cs info "$OUT/${NAME}.r1cs" 2>/dev/null | grep -E "Constraints|Variables" | sed 's/^/    /'

  echo ""
done

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Trusted setup complete!${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""
echo "  Files generated:"
echo ""
echo "  $POT_FINAL"
for NAME in "${!CIRCUITS[@]}"; do
  echo "  $BUILD_DIR/$NAME/${NAME}.zkey"
  echo "  $BUILD_DIR/$NAME/${NAME}_vkey.json"
  echo "  $BUILD_DIR/$NAME/${NAME}_js/${NAME}.wasm"
done
echo ""
echo -e "  Run ${CYAN}./scripts/generate_proof.sh${RESET} to generate a proof."
echo ""
