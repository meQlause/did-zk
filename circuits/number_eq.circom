pragma circom 2.0.0;

include "validators.circom";

/*
  number_eq.circom
  ─────────────────
  Entry point: NumberEQValidator
  Proves: value == threshold  (Number field, type 2)

  Private inputs:  value, key, typ
  Public inputs:   threshold, fieldHash, credentialRoot
  Output:          valid
*/

component main {
    public [threshold, fieldHash, credentialRoot]
} = NumberEQValidator();
