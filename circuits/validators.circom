pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 ═══════════════════════════════════════════════════════════════════
  validators.circom
  One template per (type, operation) combination.

  All validators share the same pattern:
    Private:  value, key, typ
    Public:   constraint inputs + fieldHash + credentialRoot
    Output:   valid (0 or 1)

  Step 1 in every validator: re-derive fieldHash and assert equality.
    This proves the private value is the one committed in the credential.
  Step 2: evaluate the specific constraint.
 ═══════════════════════════════════════════════════════════════════
*/


/* ─── NumberGTValidator ────────────────────────────────────────────
   Type:   Number (2)
   Proves: value > threshold
   Also covers: lt (flip inputs), lte (threshold = val - 1)
*/
template NumberGTValidator() {
    signal input value;
    signal input key;
    signal input typ;
    signal input threshold;
    signal input fieldHash;
    signal input credentialRoot;
    signal output valid;

    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    // value > threshold  ↔  value >= threshold + 1
    component gt = GreaterEqThan(64);
    gt.in[0] <== value;
    gt.in[1] <== threshold + 1;
    valid <== gt.out;
}


/* ─── NumberRangeValidator ─────────────────────────────────────────
   Type:   Number (2)
   Proves: minVal <= value <= maxVal
   Also covers: gte (minVal = val, maxVal = 2^64-1)
*/
template NumberRangeValidator() {
    signal input value;
    signal input key;
    signal input typ;
    signal input minVal;
    signal input maxVal;
    signal input fieldHash;
    signal input credentialRoot;
    signal output valid;

    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    component geMin = GreaterEqThan(64);
    geMin.in[0] <== value;
    geMin.in[1] <== minVal;

    component leMax = LessEqThan(64);
    leMax.in[0] <== value;
    leMax.in[1] <== maxVal;

    valid <== geMin.out * leMax.out;
}


/* ─── NumberEQValidator ────────────────────────────────────────────
   Type:   Number (2)
   Proves: value == expected
*/
template NumberEQValidator() {
    signal input value;
    signal input key;
    signal input typ;
    signal input threshold;    // the expected value
    signal input fieldHash;
    signal input credentialRoot;
    signal output valid;

    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    component eq = IsEqual();
    eq.in[0] <== value;
    eq.in[1] <== threshold;
    valid <== eq.out;
}


/* ─── DateRangeValidator ───────────────────────────────────────────
   Type:   Date (3)
   Encoding: YYYY-MM-DD → YYYYMMDD integer (e.g. 19990115)
   Proves: afterDate <= value <= beforeDate
   For gt/lt: set the other bound to 0 or a far-future date.
*/
template DateRangeValidator() {
    signal input value;         // date as YYYYMMDD integer
    signal input key;
    signal input typ;           // must be 3
    signal input afterDate;     // inclusive lower bound (public)
    signal input beforeDate;    // inclusive upper bound (public)
    signal input fieldHash;
    signal input credentialRoot;
    signal output valid;

    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    component geAfter = GreaterEqThan(32);
    geAfter.in[0] <== value;
    geAfter.in[1] <== afterDate;

    component leBefore = LessEqThan(32);
    leBefore.in[0] <== value;
    leBefore.in[1] <== beforeDate;

    valid <== geAfter.out * leBefore.out;
}


/* ─── TextHashEQValidator ──────────────────────────────────────────
   Types:  Text (0), Email (1), Long Text (5)
   Proves: Poseidon(value) == expectedValueHash
   The raw text is NEVER revealed; only its hash appears in public signals.
*/
template TextHashEQValidator() {
    signal input value;              // encoded text as felt (private)
    signal input key;
    signal input typ;
    signal input expectedValueHash;  // Poseidon(expected_value) — public
    signal input fieldHash;
    signal input credentialRoot;
    signal output valid;

    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    component vh = Poseidon(1);
    vh.inputs[0] <== value;

    component eq = IsEqual();
    eq.in[0] <== vh.out;
    eq.in[1] <== expectedValueHash;
    valid <== eq.out;
}


/* ─── AttachmentFileValidator ──────────────────────────────────────
   Type:   Attachment File (4)

   An Attachment field VALUE is already a hash — the fingerprint of a
   referenced external document (another credential, contract, etc.).

   Validation = direct equality: stored_hash == expectedDocHash.
   No secondary hashing is applied (unlike text fields) because the
   value itself is a document reference, not a secret value.

   Private:  value (the doc hash stored in the field), key, typ
   Public:   expectedDocHash, fieldHash, credentialRoot
*/
template AttachmentFileValidator() {
    signal input value;            // the doc hash stored in the field (as felt)
    signal input key;
    signal input typ;              // must be 4
    signal input expectedDocHash;  // exact doc hash the verifier expects (public)
    signal input fieldHash;        // committed field hash inside credential (public)
    signal input credentialRoot;   // the known credential root (public)
    signal output valid;

    // Step 1: Prove field membership
    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    // Step 2: Direct equality — value IS a hash, no wrapping
    component eq = IsEqual();
    eq.in[0] <== value;
    eq.in[1] <== expectedDocHash;
    valid <== eq.out;
}


// ── Compiled entry points (one per circuit file in production) ────────────────
// In production each template lives in its own file with a `component main` line:
//
//   number_gt.circom:          component main {public [...]} = NumberGTValidator();
//   number_range.circom:       component main {public [...]} = NumberRangeValidator();
//   number_eq.circom:          component main {public [...]} = NumberEQValidator();
//   date_range.circom:         component main {public [...]} = DateRangeValidator();
//   text_hash_eq.circom:       component main {public [...]} = TextHashEQValidator();
//   attachment_hash_eq.circom: component main {public [...]} = AttachmentFileValidator();
