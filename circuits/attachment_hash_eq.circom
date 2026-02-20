pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
  attachment_hash_eq.circom
  ──────────────────────────
  Attachment File field validator.

  The field value IS the hash of a referenced external document.
  Proves: stored_doc_hash == expectedDocHash  (direct equality)

  Private:  value, key, typ
  Public:   expectedDocHash, fieldHash, credentialRoot
*/
template AttachmentFileValidator() {
    signal input value;
    signal input key;
    signal input typ;
    signal input expectedDocHash;
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
    eq.in[1] <== expectedDocHash;
    valid <== eq.out;
}

component main {
    public [expectedDocHash, fieldHash, credentialRoot]
} = AttachmentFileValidator();
