# setup_zk.ps1 — ZK-Identity full pipeline (all 6 credential types)
# Synchronized with setup_zk.sh logic

$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────
$CircuitName = "selective_disclosure"
$CircuitsDir = "circuits"
$BuildDir = "build_zk"
$InputsDir = "zk_inputs"
$PtauSize = 14   # 2^14 = 16384 constraints

# ─────────────────────────────────────────────────────────────────────────────
# Derived paths
# ─────────────────────────────────────────────────────────────────────────────
$PTAU_0 = "$BuildDir/pot$PtauSize`_0000.ptau"
$PTAU_1 = "$BuildDir/pot$PtauSize`_0001.ptau"
$PTAU_FINAL = "$BuildDir/pot$PtauSize`_final.ptau"
$R1CS = "$BuildDir/$($CircuitName).r1cs"
$WASM = "$BuildDir/$($CircuitName)_js/$($CircuitName).wasm"
$ZKEY_0 = "$BuildDir/$($CircuitName)_0000.zkey"
$ZKEY_FINAL = "$BuildDir/$($CircuitName)_final.zkey"
$VKEY = "$BuildDir/verification_key.json"

if (!(Test-Path $BuildDir)) { New-Item -ItemType Directory $BuildDir }

function Write-Ok ($msg) { Write-Host "  ✔ $msg" -ForegroundColor Green }
function Write-Info ($msg) { Write-Host "`n━━━ $msg ━━━" -ForegroundColor Cyan }
function Write-Warn ($msg) { Write-Host "  ⚠ $msg" -ForegroundColor Yellow }
function Write-Fail ($msg) { Write-Host "  ✘ $msg" -ForegroundColor Red; exit 1 }

# ─────────────────────────────────────────────────────────────────────────────
# 1. Powers of Tau — Phase 1
# ─────────────────────────────────────────────────────────────────────────────
Write-Info "1. Powers of Tau Phase 1"

if (!(Test-Path $PTAU_FINAL)) {
    Write-Host "  Generating Powers of Tau (size=$PtauSize)..."

    npx snarkjs powersoftau new bn128 $PtauSize "$PTAU_0" -v
    
    $entropy = [Convert]::ToBase64String((1..10 | foreach { Get-Random -Minimum 0 -Maximum 256 }))
    npx snarkjs powersoftau contribute "$PTAU_0" "$PTAU_1" --name="First contribution" -v -e="$entropy"

    npx snarkjs powersoftau prepare phase2 "$PTAU_1" "$PTAU_FINAL" -v
    Write-Ok "ptau finalised → $PTAU_FINAL"
} else {
    Write-Ok "Cached: $PTAU_FINAL"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. Compile Circuit
# ─────────────────────────────────────────────────────────────────────────────
Write-Info "2. Compile Circuit"
Write-Host "  Compiling $($CircuitsDir)/$($CircuitName).circom..."

& circom "$($CircuitsDir)/$($CircuitName).circom" `
  --r1cs --wasm --sym `
  -l ./node_modules `
  -o "$BuildDir"

Write-Ok "r1cs → $R1CS"
Write-Ok "wasm → $WASM"

# Print constraint count
npx snarkjs r1cs info "$R1CS" | Select-String "Constraints|Wires" | foreach { Write-Host "  $($_.Line.Trim())" }

# ─────────────────────────────────────────────────────────────────────────────
# 3. Groth16 Trusted Setup — Phase 2
# ─────────────────────────────────────────────────────────────────────────────
Write-Info "3. Groth16 Trusted Setup (Phase 2)"

if (!(Test-Path $ZKEY_FINAL)) {
    Write-Host "  Generating zkey..."
    npx snarkjs groth16 setup "$R1CS" "$PTAU_FINAL" "$ZKEY_0"

    Write-Host "  Contributing randomness..."
    $entropy = [Convert]::ToBase64String((1..10 | foreach { Get-Random -Minimum 0 -Maximum 256 }))
    npx snarkjs zkey contribute "$ZKEY_0" "$ZKEY_FINAL" --name="1st Contributor Name" -v -e="$entropy"

    Write-Ok "zkey → $ZKEY_FINAL"
} else {
    Write-Ok "Cached: $ZKEY_FINAL"
}

npx snarkjs zkey export verificationkey "$ZKEY_FINAL" "$VKEY"
Write-Ok "Verification key → $VKEY"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Build complete
# ─────────────────────────────────────────────────────────────────────────────
Write-Info "4. Build Complete"
Write-Host "  BuildDir         : $BuildDir"
Write-Host "  Verification key : $VKEY"
Write-Host "  WASM             : $WASM"
Write-Host "  Final zkey       : $ZKEY_FINAL"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Prove & verify — all credential types via proof_manifest.json
# ─────────────────────────────────────────────────────────────────────────────
Write-Info "5. Proving All Credential Types"

$ManifestPath = "$InputsDir/proof_manifest.json"
if (!(Test-Path $ManifestPath)) {
    Write-Warn "$ManifestPath not found — run 'npm run demo' first"
    
    # Legacy fallback
    foreach ($legacy in @("age", "email")) {
        $input = "$InputsDir/input_$legacy.json"
        if (Test-Path $input) {
            Write-Host "`n  ── $legacy (legacy) ──"
            $proof = "$BuildDir/$legacy`_proof.json"
            $public = "$BuildDir/$legacy`_public.json"
            Write-Host -NoNewline "     Proving... "
            npx snarkjs groth16 fullProve "$input" "$WASM" "$ZKEY_FINAL" "$proof" "$public"
            Write-Host "done" -ForegroundColor Green
            
            Write-Host -NoNewline "     Verifying... "
            $verify = npx snarkjs groth16 verify "$VKEY" "$public" "$proof"
            if ($verify -match "OK") { Write-Host "VALID ✔" -ForegroundColor Green }
            else { Write-Host "INVALID ✘" -ForegroundColor Red }
        }
    }
    exit 0
}

$manifest = Get-Content $ManifestPath | ConvertFrom-Json
$passCount = 0
$failCount = 0
$results = @{}

foreach ($entry in $manifest) {
    Write-Host "`n  ── $($entry.label) (type=$($entry.type)) ──" -ForegroundColor Cyan
    
    $inputFile = $entry.inputFile
    # Slug from inputFile: "zk_inputs/input_email.json" -> "email"
    $filename = Split-Path $inputFile -Leaf
    $slug = ($filename -replace "input_", "") -replace ".json", ""
    
    $proofFile = "$BuildDir/proof_$slug.json"
    $publicFile = "$BuildDir/public_$slug.json"
    
    if (!(Test-Path $inputFile)) {
        Write-Warn "Missing: $inputFile — skipping"
        $results[$entry.label] = "FAIL: missing"
        $failCount++
        continue
    }
    
    Write-Host -NoNewline "     Proving...   "
    try {
        npx snarkjs groth16 fullProve "$inputFile" "$WASM" "$ZKEY_FINAL" "$proofFile" "$publicFile"
        Write-Host "done" -ForegroundColor Green
    } catch {
        Write-Host "FAILED" -ForegroundColor Red
        $results[$entry.label] = "FAIL: proving error"
        $failCount++
        continue
    }
    
    Write-Host -NoNewline "     Verifying... "
    $verify = npx snarkjs groth16 verify "$VKEY" "$publicFile" "$proofFile"
    if ($verify -match "OK") {
        Write-Host "VALID ✔" -ForegroundColor Green
        $results[$entry.label] = "PASS"
        $passCount++
    } else {
        Write-Host "INVALID ✘" -ForegroundColor Red
        $results[$entry.label] = "FAIL: verification rejected"
        $failCount++
    }
    
    # Public signals
    Write-Host "     Public signals:"
    $sigs = Get-Content $publicFile | ConvertFrom-Json
    $lbls = @("key", "credentialRoot", "publicCommitment", "threshold", "expectedValueHash")
    for ($i=0; $i -lt $sigs.Count; $i++) {
        $val = $sigs[$i]
        $short = if ($val.Length -gt 24) { $val.Substring(0, 24) + "..." } else { $val }
        Write-Host ("       [{0}] {1, -20} = {2}" -f $i, $lbls[$i], $short)
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. Results summary
# ─────────────────────────────────────────────────────────────────────────────
Write-Info "6. Results Summary"
Write-Host ("  {0, -26} {1}" -f "Credential Type", "Result")
Write-Host ("  {0, -26} {1}" -f "──────────────────────────", "──────")

foreach ($label in $results.Keys) {
    $status = $results[$label]
    if ($status -eq "PASS") {
        Write-Host ("  {0, -26} " -f $label) -NoNewline
        Write-Host $status -ForegroundColor Green
    } else {
        Write-Host ("  {0, -26} " -f $label) -NoNewline
        Write-Host $status -ForegroundColor Red
    }
}

Write-Host "`n  Total: $passCount passed, $failCount failed"
if ($failCount -eq 0) { Write-Ok "All proofs valid." } else { Write-Fail "$failCount proof(s) failed." }
