# setup_zk.ps1
# Automates the SnarkJS pipeline for DID-zk

$CircuitName = "selective_disclosure"
$CircuitsDir = "circuits"
$BuildDir = "build_zk"
$PtauSize = 12 # 2^12 = 4096 constraints, enough for our small circuit

# Create build directory
if (!(Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir
}

Write-Host "━━━ 1. Powers of Tau Phase 1 ━━━" -ForegroundColor Cyan
if (!(Test-Path "$BuildDir/pot${PtauSize}_final.ptau")) {
    Write-Host "Generating new Powers of Tau..."
    npx snarkjs powersoftau new bn128 $PtauSize "$BuildDir/pot${PtauSize}_0000.ptau" -v
    npx snarkjs powersoftau contribute "$BuildDir/pot${PtauSize}_0000.ptau" "$BuildDir/pot${PtauSize}_0001.ptau" --name="First contribution" -v -e="$(Get-Random)"
    npx snarkjs powersoftau prepare phase2 "$BuildDir/pot${PtauSize}_0001.ptau" "$BuildDir/pot${PtauSize}_final.ptau" -v
} else {
    Write-Host "Final ptau already exists, skipping."
}

Write-Host "`n━━━ 2. Compile Circuit ━━━" -ForegroundColor Cyan
Write-Host "Compiling $CircuitName.circom..."
npx circom "$CircuitsDir/$CircuitName.circom" --r1cs --wasm --sym --output $BuildDir

Write-Host "`n━━━ 3. Setup Groth16 (Phase 2) ━━━" -ForegroundColor Cyan
Write-Host "Generating zkey..."
npx snarkjs groth16 setup "$BuildDir/$CircuitName.r1cs" "$BuildDir/pot${PtauSize}_final.ptau" "$BuildDir/${CircuitName}_0000.zkey"
npx snarkjs zkey contribute "$BuildDir/${CircuitName}_0000.zkey" "$BuildDir/${CircuitName}_final.zkey" --name="1st Contributor Name" -v -e="$(Get-Random)"
npx snarkjs zkey export verificationkey "$BuildDir/${CircuitName}_final.zkey" "$BuildDir/verification_key.json"

Write-Host "`n━━━ 4. Build Completed ━━━" -ForegroundColor Green
Write-Host "Artifacts are in the '$BuildDir' directory."
Write-Host "Verification key: $BuildDir/verification_key.json"
Write-Host "WASM: $BuildDir/${CircuitName}_js/${CircuitName}.wasm"

# Optional: Try to generate a test proof if input exists
if (Test-Path "input_age.json") {
    Write-Host "`n━━━ 5. Generating Test Proof (input_age.json) ━━━" -ForegroundColor Cyan
    npx snarkjs groth16 fullProve "input_age.json" "$BuildDir/${CircuitName}_js/${CircuitName}.wasm" "$BuildDir/${CircuitName}_final.zkey" "$BuildDir/proof.json" "$BuildDir/public.json"
    
    Write-Host "Verifying Test Proof..."
    npx snarkjs groth16 verify "$BuildDir/verification_key.json" "$BuildDir/public.json" "$BuildDir/proof.json"
}
