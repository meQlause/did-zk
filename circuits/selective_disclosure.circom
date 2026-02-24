pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/switcher.circom";

// ─────────────────────────────────────────────────────────────────────────────
// MerkleProof – depth 8, Poseidon(2) nodes
// ─────────────────────────────────────────────────────────────────────────────
template MerkleProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    component hashers[depth];
    component switchers[depth];
    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L   <== levelHashes[i];
        switchers[i].R   <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[depth];
}

// ─────────────────────────────────────────────────────────────────────────────
// IsNumericType – 1 iff typ ∈ {2, 3}
// ─────────────────────────────────────────────────────────────────────────────
template IsNumericType() {
    signal input typ;
    signal output out;

    component eq2 = IsEqual();
    eq2.in[0] <== typ;
    eq2.in[1] <== 2;

    component eq3 = IsEqual();
    eq3.in[0] <== typ;
    eq3.in[1] <== 3;

    // Boolean OR: a + b - a*b  (safe: they can't both be 1)
    out <== eq2.out + eq3.out - eq2.out * eq3.out;
}

// ─────────────────────────────────────────────────────────────────────────────
// SelectiveDisclosure – main circuit
// ─────────────────────────────────────────────────────────────────────────────
template SelectiveDisclosure() {

    // ── Private inputs ───────────────────────────────────────────────────────
    signal input typ;
    signal input value;
    signal input salt;
    signal input pathElements[8];
    signal input pathIndices[8];
    signal input identitySecret;

    // ── Public inputs ────────────────────────────────────────────────────────
    signal input key;
    signal input credentialRoot;
    signal input walletAddress;
    signal input threshold;
    signal input expectedValueHash;

    // ════════════════════════════════════════════════════════════════════════
    // 1. WALLET BINDING  –  Poseidon(identitySecret) === walletAddress
    // ════════════════════════════════════════════════════════════════════════
    component walletHasher = Poseidon(1);
    walletHasher.inputs[0] <== identitySecret;
    walletHasher.out === walletAddress;

    // ════════════════════════════════════════════════════════════════════════
    // 2. LEAF CONSTRUCTION  –  Poseidon(key, typ, value, salt)
    // ════════════════════════════════════════════════════════════════════════
    component leafHasher = Poseidon(4);
    leafHasher.inputs[0] <== key;
    leafHasher.inputs[1] <== typ;
    leafHasher.inputs[2] <== value;
    leafHasher.inputs[3] <== salt;

    // ════════════════════════════════════════════════════════════════════════
    // 3. MERKLE ROOT VERIFICATION
    // ════════════════════════════════════════════════════════════════════════
    component merkle = MerkleProof(8);
    merkle.leaf <== leafHasher.out;
    for (var i = 0; i < 8; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i]  <== pathIndices[i];
    }
    merkle.root === credentialRoot;

    // ════════════════════════════════════════════════════════════════════════
    // 4. TYPE ROUTING
    // ════════════════════════════════════════════════════════════════════════
    component typeCheck = IsNumericType();
    typeCheck.typ <== typ;
    signal isNumeric <== typeCheck.out;

    // ════════════════════════════════════════════════════════════════════════
    // 4a. NUMERIC CHECK  –  value >= threshold
    //
    // ROOT CAUSE OF THE BUG:
    //   GreaterEqThan(N) internally calls Num2Bits(N) on BOTH inputs.
    //   When typ is non-numeric (e.g. EMAIL), `value` is a full BN254 field
    //   element (~254 bits).  Passing it into GreaterEqThan(64) overflows
    //   Num2Bits(64) and throws "Assert Failed" at witness generation time —
    //   even though the numeric branch is logically unused.
    //
    // FIX (two-part):
    //   (a) Use GreaterEqThan(252) — wide enough for any value we store.
    //       252 bits safely covers dates (≤ 2^27), numbers, and field elements.
    //       Cost: ~252 extra constraints, acceptable for a non-browser prover.
    //
    //   (b) Feed the comparator a MASKED value:
    //           maskedValue = isNumeric * value
    //       When isNumeric=0 (string type), maskedValue=0, so Num2Bits(252)
    //       receives 0 — always a valid 252-bit integer regardless of what
    //       `value` actually is.  The numeric constraint is then trivially
    //       satisfied (0 >= 0) but we gate the enforcement below so it is
    //       only checked when isNumeric=1.
    // ════════════════════════════════════════════════════════════════════════

    // Mask value to 0 when not a numeric type → Num2Bits never overflows
    signal maskedValue <== isNumeric * value;

    // Also mask threshold so the comparator input is always valid
    signal maskedThreshold <== isNumeric * threshold;

    component gte = GreaterEqThan(252);
    gte.in[0] <== maskedValue;
    gte.in[1] <== maskedThreshold;

    // Enforce: IF isNumeric THEN gte.out must be 1
    // isNumeric * (1 - gte.out) === 0
    signal numericOk <== isNumeric * (1 - gte.out);
    numericOk === 0;

    // ════════════════════════════════════════════════════════════════════════
    // 4b. HASH EQUALITY CHECK  –  Poseidon(value) === expectedValueHash
    //
    // This branch always computes Poseidon(value) but only enforces equality
    // when isNumeric=0.  No overflow risk here because Poseidon accepts any
    // field element as input.
    // ════════════════════════════════════════════════════════════════════════
    component valueHasher = Poseidon(1);
    valueHasher.inputs[0] <== value;

    signal hashDiff <== valueHasher.out - expectedValueHash;

    // Enforce: IF NOT isNumeric THEN hashDiff must be 0
    // (1 - isNumeric) * hashDiff === 0
    signal hashOk <== (1 - isNumeric) * hashDiff;
    hashOk === 0;
}

component main {public [key, credentialRoot, walletAddress, threshold, expectedValueHash]} = SelectiveDisclosure();
