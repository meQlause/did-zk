pragma circom 2.0.0;

include "validators.circom";

/*
  number_range.circom
  ────────────────────
  Entry point: NumberRangeValidator
  Proves: minVal <= value <= maxVal  (Number field, type 2)

  Private inputs:  value, key, typ
  Public inputs:   minVal, maxVal, fieldHash, credentialRoot
  Output:          valid
*/

component main {
    public [minVal, maxVal, fieldHash, credentialRoot]
} = NumberRangeValidator();
