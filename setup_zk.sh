#!/bin/bash
# setup_zk.sh
# Automates the SnarkJS pipeline for DID-zk

CircuitName="selective_disclosure"
CircuitsDir="circuits"
BuildDir="build_zk"
PtauSize=12 # 2^12 = 4096 constraints, enough for our small circuit

# Colors for output
CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Create build directory
if [ ! -d "$BuildDir" ]; then
    mkdir -p "$BuildDir"
fi

echo -e "${CYAN}━━━ 1. Powers of Tau Phase 1 ━━━${NC}"
if [ ! -f "$BuildDir/pot${PtauSize}_final.ptau" ]; then
    echo "Generating new Powers of Tau..."
    npx snarkjs powersoftau new bn128 $PtauSize "$BuildDir/pot${PtauSize}_0000.ptau" -v
    npx snarkjs powersoftau contribute "$BuildDir/pot${PtauSize}_0000.ptau" "$BuildDir/pot${PtauSize}_0001.ptau" --name="First contribution" -v -e="$(head -c 10 /dev/urandom | base64)"
    npx snarkjs powersoftau prepare phase2 "$BuildDir/pot${PtauSize}_0001.ptau" "$BuildDir/pot${PtauSize}_final.ptau" -v
else
    echo "Final ptau already exists, skipping."
fi

echo -e "\n${CYAN}━━━ 2. Compile Circuit ━━━${NC}"
echo "Compiling $CircuitName.circom..."
npx circom "$CircuitsDir/$CircuitName.circom" --r1cs --wasm --sym --output "$BuildDir"

echo -e "\n${CYAN}━━━ 3. Setup Groth16 (Phase 2) ━━━${NC}"
echo "Generating zkey..."
npx snarkjs groth16 setup "$BuildDir/$CircuitName.r1cs" "$BuildDir/pot${PtauSize}_final.ptau" "$BuildDir/${CircuitName}_0000.zkey"
npx snarkjs zkey contribute "$BuildDir/${CircuitName}_0000.zkey" "$BuildDir/${CircuitName}_final.zkey" --name="1st Contributor Name" -v -e="$(head -c 10 /dev/urandom | base64)"
npx snarkjs zkey export verificationkey "$BuildDir/${CircuitName}_final.zkey" "$BuildDir/verification_key.json"

echo -e "\n${GREEN}━━━ 4. Build Completed ━━━${NC}"
echo "Artifacts are in the '$BuildDir' directory."
echo "Verification key: $BuildDir/verification_key.json"
echo "WASM: $BuildDir/${CircuitName}_js/${CircuitName}.wasm"

# Optional: Try to generate a test proof if input exists
if [ -f "input_age.json" ]; then
    echo -e "\n${CYAN}━━━ 5. Generating Test Proof (input_age.json) ━━━${NC}"
    npx snarkjs groth16 fullProve "input_age.json" "$BuildDir/${CircuitName}_js/${CircuitName}.wasm" "$BuildDir/${CircuitName}_final.zkey" "$BuildDir/proof.json" "$BuildDir/public.json"
    
    echo "Verifying Test Proof..."
    npx snarkjs groth16 verify "$BuildDir/verification_key.json" "$BuildDir/public.json" "$BuildDir/proof.json"
fi
