pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/switcher.circom";
include "node_modules/circomlib/circuits/mux1.circom";

// ─────────────────────────────────────────────────────────────────────────────
// MerkleProof – depth 8, Poseidon(2) nodes
// ─────────────────────────────────────────────────────────────────────────────
template MerkleProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];  // 0 = leaf is left child, 1 = leaf is right child
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
// IsNumericType – returns 1 if typ ∈ {2, 3}
// Implemented without branching: isNum = isType2 OR isType3
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

    // out = eq2 + eq3 - eq2*eq3  (OR without overflow, since they can't both be 1)
    out <== eq2.out + eq3.out - eq2.out * eq3.out;
}

// ─────────────────────────────────────────────────────────────────────────────
// SelectiveDisclosure – main circuit
// ─────────────────────────────────────────────────────────────────────────────
template SelectiveDisclosure() {

    // ── Private inputs ──────────────────────────────────────────────────────
    signal input key;             // field label identifier
    signal input typ;             // type enum 0-5
    signal input value;           // the credential value
    signal input salt;            // random blinding factor
    signal input pathElements[8]; // sibling hashes on the Merkle path
    signal input pathIndices[8];  // 0/1 direction at each level
    signal input identitySecret;  // secret that binds to walletAddress

    // ── Public inputs ────────────────────────────────────────────────────────
    signal input credentialRoot;    // on-chain Merkle root
    signal input walletAddress;     // keccak-truncated address stored as field
    signal input threshold;         // used when typ ∈ {2,3}
    signal input expectedValueHash; // used when typ ∈ {0,1,4,5}

    // ════════════════════════════════════════════════════════════════════════
    // 1. WALLET BINDING
    //    Prove: Poseidon(identitySecret) == walletAddress
    // ════════════════════════════════════════════════════════════════════════
    component walletHasher = Poseidon(1);
    walletHasher.inputs[0] <== identitySecret;
    walletHasher.out === walletAddress;

    // ════════════════════════════════════════════════════════════════════════
    // 2. LEAF CONSTRUCTION
    //    leaf = Poseidon(key, typ, value, salt)
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
    // 4. CONDITIONAL CLAIM VERIFICATION
    //
    //    isNumeric = 1  →  assert value >= threshold
    //    isNumeric = 0  →  assert Poseidon(value) == expectedValueHash
    //
    //    Both checks are computed; only the relevant one is enforced via
    //    a constraint that evaluates to 0 regardless of the unused branch.
    // ════════════════════════════════════════════════════════════════════════
    component typeCheck = IsNumericType();
    typeCheck.typ <== typ;
    signal isNumeric <== typeCheck.out;

    // ── 4a. Numeric check: value >= threshold ────────────────────────────────
    // GreaterEqThan works on n-bit integers. We use 64 bits which covers
    // dates (up to 99991231) and reasonable numeric credential values.
    component gte = GreaterEqThan(64);
    gte.in[0] <== value;
    gte.in[1] <== threshold;
    // gte.out == 1 means value >= threshold

    // Enforce: if isNumeric == 1, then gte.out must be 1
    // Constraint: isNumeric * (1 - gte.out) === 0
    signal numericOk <== isNumeric * (1 - gte.out);
    numericOk === 0;

    // ── 4b. Hash equality check: Poseidon(value) == expectedValueHash ────────
    component valueHasher = Poseidon(1);
    valueHasher.inputs[0] <== value;

    signal hashDiff <== valueHasher.out - expectedValueHash;

    // Enforce: if isNumeric == 0, then hashDiff must be 0
    // Constraint: (1 - isNumeric) * hashDiff === 0
    signal hashOk <== (1 - isNumeric) * hashDiff;
    hashOk === 0;
}

component main {public [credentialRoot, walletAddress, threshold, expectedValueHash]} = SelectiveDisclosure();
