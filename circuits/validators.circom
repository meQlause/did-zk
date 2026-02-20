pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 ═══════════════════════════════════════════════════════════════════
  validators.circom
  Pure template library — ONE template per (type, operation).
  No `component main` here. Each entry-point file includes this
  file and declares its own `component main`.

  All validators share the same pattern:
    Private:  value, key, typ
    Public:   constraint inputs + fieldHash + credentialRoot
    Output:   valid (0 or 1)

  Step 1: re-derive fieldHash and assert equality.
          Proves the private value is the one committed in the credential.
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

    // Step 1: bind private value to the committed fieldHash
    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    // Step 2: value > threshold  ↔  value >= threshold + 1
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

    // Step 1
    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    // Step 2
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

    // Step 1
    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    // Step 2
    component eq = IsEqual();
    eq.in[0] <== value;
    eq.in[1] <== threshold;
    valid <== eq.out;
}


/* ─── DateRangeValidator ───────────────────────────────────────────
   Type:   Date (3)
   Encoding: YYYY-MM-DD → YYYYMMDD integer (e.g. 19990115)
   Proves: afterDate <= value <= beforeDate
   For open-ended bounds: afterDate = 0  or  beforeDate = 99991231
*/
template DateRangeValidator() {
    signal input value;         // date as YYYYMMDD integer (private)
    signal input key;
    signal input typ;           // must be 3
    signal input afterDate;     // inclusive lower bound (public)
    signal input beforeDate;    // inclusive upper bound (public)
    signal input fieldHash;
    signal input credentialRoot;
    signal output valid;

    // Step 1
    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    // Step 2
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

    // Step 1
    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    // Step 2: compare hashes, never expose raw value
    component vh = Poseidon(1);
    vh.inputs[0] <== value;

    component eq = IsEqual();
    eq.in[0] <== vh.out;
    eq.in[1] <== expectedValueHash;
    valid <== eq.out;
}


/* ─── AttachmentFileValidator ──────────────────────────────────────
   Type:   Attachment File (4)
   The field VALUE is already a doc hash (not a secret scalar).
   Proves: stored_doc_hash == expectedDocHash  (direct equality)

   Private:  value (doc hash stored in the field), key, typ
   Public:   expectedDocHash, fieldHash, credentialRoot
*/
template AttachmentFileValidator() {
    signal input value;            // doc hash stored in the field (private)
    signal input key;
    signal input typ;              // must be 4
    signal input expectedDocHash;  // exact hash the verifier expects (public)
    signal input fieldHash;
    signal input credentialRoot;
    signal output valid;

    // Step 1
    component fh = Poseidon(3);
    fh.inputs[0] <== key;
    fh.inputs[1] <== typ;
    fh.inputs[2] <== value;
    fh.out === fieldHash;

    // Step 2: direct equality — value IS a hash, no wrapping needed
    component eq = IsEqual();
    eq.in[0] <== value;
    eq.in[1] <== expectedDocHash;
    valid <== eq.out;
}
