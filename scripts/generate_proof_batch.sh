#!/usr/bin/env bash
# =============================================================================
# generate_proof_batch.sh
# Generates proofs for ALL rules in a proof-bundle.json (exported from prover page).
#
# Usage:
#   ./scripts/generate_proof_batch.sh <proof-bundle.json>
#
# Example:
#   ./scripts/generate_proof_batch.sh proofs/proof-bundle.json
#
# Reads the witnessInputs for each proof entry, runs generate_proof.sh for
# each one, then assembles a final verified bundle with real proofs.
# =============================================================================

set -e

BUNDLE_FILE="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_SCRIPT="$SCRIPT_DIR/generate_proof.sh"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'
log() { echo -e "${CYAN}[batch]${RESET} $*"; }
ok()  { echo -e "${GREEN}[  ok ]${RESET} $*"; }
err() { echo -e "${RED}[error]${RESET} $*"; exit 1; }

[ -z "$BUNDLE_FILE" ] && { echo "Usage: $0 <proof-bundle.json>"; exit 0; }
[ -f "$BUNDLE_FILE" ] || err "File not found: $BUNDLE_FILE"
[ -f "$GEN_SCRIPT"  ] || err "generate_proof.sh not found at $SCRIPT_DIR"

command -v python3 >/dev/null 2>&1 || err "python3 required for batch script"
command -v snarkjs >/dev/null 2>&1 || err "snarkjs not found"

echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  ZK Credential — Batch Proof Generation${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}\n"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BATCH_DIR="proofs/batch_${TIMESTAMP}"
mkdir -p "$BATCH_DIR"

# Extract each proof's witnessInputs and circuit from the bundle using python3
python3 - "$BUNDLE_FILE" "$BATCH_DIR" "$GEN_SCRIPT" <<'PYEOF'
import json, subprocess, sys, os, shutil

bundle_file = sys.argv[1]
batch_dir   = sys.argv[2]
gen_script  = sys.argv[3]

with open(bundle_file) as f:
  bundle = json.load(f)

proofs      = bundle.get("proofs", [])
cred_root   = bundle.get("credentialRoot", "")
results     = []
total       = len(proofs)
valid_count = 0

print(f"  Credential root: {cred_root}")
print(f"  Proofs to generate: {total}\n")

for i, p in enumerate(proofs):
  circuit_name = p.get("circuit", "").replace(".circom", "")
  inputs       = p.get("witnessInputs", {})
  rule         = p.get("rule", {})
  field        = p.get("field", {})

  print(f"  [{i+1}/{total}] {rule.get('key','?')} → {circuit_name}")

  # Add label hints to inputs for bundle reconstruction
  inputs["_key_label"] = rule.get("key", "field")

  inputs_path = os.path.join(batch_dir, f"inputs_{i}.json")
  with open(inputs_path, "w") as f:
    json.dump(inputs, f)

  try:
    result = subprocess.run(
      ["bash", gen_script, circuit_name, inputs_path],
      capture_output=True, text=True
    )

    if result.returncode == 0 and "VALID" in result.stdout:
      # Find the most recently created proof dir
      proof_dir = sorted(
        [d for d in os.listdir("proofs") if d.startswith(circuit_name)],
        reverse=True
      )[0]
      proof_path  = os.path.join("proofs", proof_dir, "proof.json")
      public_path = os.path.join("proofs", proof_dir, "public.json")

      with open(proof_path)  as f: proof_data   = json.load(f)
      with open(public_path) as f: public_sigs  = json.load(f)

      p["proof"]         = proof_data
      p["publicSignals"] = public_sigs
      p["valid"]         = True
      valid_count += 1
      print(f"    ✓ VALID")
    else:
      p["valid"] = False
      print(f"    ✗ FAILED\n{result.stderr[:200]}")

  except Exception as e:
    p["valid"] = False
    print(f"    ✗ ERROR: {e}")

  results.append(p)

# Write final verified bundle
final_bundle = {
  "version":        "1.0",
  "credentialRoot": cred_root,
  "generatedAt":    bundle.get("generatedAt"),
  "batchGeneratedAt": __import__("datetime").datetime.utcnow().isoformat() + "Z",
  "proofs":         results,
}

final_path = os.path.join(batch_dir, "verified_bundle.json")
with open(final_path, "w") as f:
  json.dump(final_bundle, f, indent=2)

print(f"\n  Results: {valid_count}/{total} valid")
print(f"  Final bundle → {final_path}")
PYEOF

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
ok "Batch complete — load $BATCH_DIR/verified_bundle.json in verifier.html"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""
