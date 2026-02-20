pragma circom 2.0.0;

include "validators.circom";

/*
  text_hash_eq.circom
  ────────────────────
  Entry point: TextHashEQValidator
  Types:  Text (0), Email (1), Long Text (5)
  Proves: Poseidon(value) == expectedValueHash
  Raw text is NEVER revealed in public signals.

  Private inputs:  value, key, typ
  Public inputs:   expectedValueHash, fieldHash, credentialRoot
  Output:          valid
*/

component main {
    public [expectedValueHash, fieldHash, credentialRoot]
} = TextHashEQValidator();
