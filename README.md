# ZK Credential Validator

Zero-knowledge proof system for selective credential disclosure.
Prove field constraints against a known document hash without revealing private field values.

---

## Project Structure

```
zk-credential-v2/
│
├── prover.html                   ← Proof Generator UI
├── verifier.html                 ← Proof Verifier UI
│
├── css/
│   └── main.css                  ← Shared styles for both pages
│
├── js/
│   ├── constants.js              ← Field types, ops, encoding, circuit mapping, proof builder
│   ├── ui.js                     ← Shared DOM rendering helpers
│   ├── prover.js                 ← Proof Generator page logic
│   └── verifier.js               ← Verifier page logic
│
├── circuits/
│   ├── credential_hash.circom    ← Field and document hashing templates
│   ├── validators.circom         ← Number, Date, Text, Attachment validators
│   └── attachment_hash_eq.circom ← Attachment File validator (doc hash equality)
│
└── scripts/
    ├── trusted_setup.sh          ← Powers of Tau + per-circuit zkey generation
    ├── generate_proof.sh         ← Single proof generation (witness → proof → verify)
    └── generate_proof_batch.sh   ← Batch proof generation from a proof-bundle.json
```

---

## Field Types

| Type            | ID | Validation                          |
|-----------------|----|-------------------------------------|
| Text            | 0  | `hash_eq` — hash(value) == expected |
| Email           | 1  | `hash_eq` — hash(value) == expected |
| Number          | 2  | `gt / gte / lt / lte / eq / range`  |
| Date            | 3  | `range / gt / lt` (YYYYMMDD int)    |
| Attachment File | 4  | `doc_hash_eq` — value == docHash    |
| Long Text       | 5  | `hash_eq` — hash(value) == expected |

> **Attachment File** stores the hash of a referenced document as its value.
> Validation is a direct equality check — no secondary hashing applied.

---

## Circuits per operation

| Circuit                   | Type       | Operations              |
|---------------------------|------------|-------------------------|
| `number_gt.circom`        | Number     | gt, lt, lte             |
| `number_range.circom`     | Number     | range, gte              |
| `number_eq.circom`        | Number     | eq                      |
| `date_range.circom`       | Date       | range, gt, lt           |
| `text_hash_eq.circom`     | Text/Email | hash_eq                 |
| `attachment_hash_eq.circom` | File     | doc_hash_eq             |

---

## Quick Start

### 1 — Install dependencies

```bash
npm install -g snarkjs
# Install circom: https://docs.circom.io/getting-started/installation/
npm install circomlib      # Poseidon, comparators
```

### 2 — Trusted Setup (one-time per circuit)

```bash
chmod +x scripts/*.sh
./scripts/trusted_setup.sh
```

Generates `build/<circuit>/<circuit>.zkey` and `<circuit>_vkey.json` for all circuits.

### 3 — Open the Prover UI

```
open prover.html
```

1. Paste your predefined **credential hash**
2. Enter the private **credential fields** (key / type / value)
3. Define the **verifier rules** (e.g. `age > 18`)
4. Click **Generate Proofs**
5. Click **Export proof-bundle.json** or **Send to Verifier**

### 4 — Generate real proofs from CLI

```bash
# Single proof
./scripts/generate_proof.sh number_gt inputs/age_gt_18.json

# Batch (from proof-bundle.json exported by prover UI)
./scripts/generate_proof_batch.sh proof-bundle.json
```

### 5 — Verify in the UI

```
open verifier.html
```

Paste or load `proof-bundle.json` → click **Verify Proofs**.

### 6 — Verify from CLI

```bash
snarkjs groth16 verify \
  build/number_gt/number_gt_vkey.json \
  proofs/number_gt_<ts>/public.json \
  proofs/number_gt_<ts>/proof.json
```

---

## Flow Diagram

```
ISSUER                     PROVER                          VERIFIER
──────                     ──────                          ────────
Hash credential            Enter predefined hash           Load proof-bundle.json
  ↓                        Enter private fields            (no private values inside)
Publish root hash    →     Set verifier rules                  ↓
  0x5162bc...              Generate proofs              Verify each proof against
                             ↓                            credentialRoot
                           Export proof-bundle.json      ✓ age > 18 — Valid
                                    ↓ ─────────────────→ ✓ license == 0xfa3c... — Valid
```

---

## Notes

- The JS encoding (Poseidon simulation) is for UI preview only.
  In production, use `circomlibjs` → `buildPoseidon()` for real Poseidon hashes.
- Run trusted setup on a machine that will be destroyed, or use a multi-party ceremony.
- `POT_POWER=14` supports up to 2^14 constraints per circuit; increase for larger circuits.
