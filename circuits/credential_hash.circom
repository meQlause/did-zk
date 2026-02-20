pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 ═══════════════════════════════════════════════════════════════════
  credential_hash.circom
  Hashing templates shared by all validator circuits.
 ═══════════════════════════════════════════════════════════════════
*/

/*
  CredentialFieldHasher
  ─────────────────────
  Computes: fieldHash = Poseidon(key, typ, value)
  Binds the value to its key and type — you cannot swap values between fields.
*/
template CredentialFieldHasher() {
    signal input key;      // field key encoded as felt
    signal input typ;      // field type id (0=Text … 5=LongText)
    signal input value;    // field value encoded as felt
    signal output hash;

    component h = Poseidon(3);
    h.inputs[0] <== key;
    h.inputs[1] <== typ;
    h.inputs[2] <== value;
    hash <== h.out;
}

/*
  CredentialRootHasher(N)
  ───────────────────────
  Chain-hashes N field hashes into one root:
    root = Poseidon(…Poseidon(Poseidon(h0,h1),h2)…,hN-1)
  Pad unused slots with 0.
*/
template CredentialRootHasher(N) {
    signal input  fieldHashes[N];
    signal output root;

    component h[N-1];

    h[0] = Poseidon(2);
    h[0].inputs[0] <== fieldHashes[0];
    h[0].inputs[1] <== fieldHashes[1];

    for (var i = 1; i < N-1; i++) {
        h[i] = Poseidon(2);
        h[i].inputs[0] <== h[i-1].out;
        h[i].inputs[1] <== fieldHashes[i+1];
    }

    root <== h[N-2].out;
}
