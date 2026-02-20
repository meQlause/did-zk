pragma circom 2.0.0;

include "validators.circom";

/*
  date_range.circom
  ──────────────────
  Entry point: DateRangeValidator
  Proves: afterDate <= value <= beforeDate  (Date field, type 3)
  Date encoding: YYYYMMDD integer (e.g. 19990115)

  For open-ended bounds:
    - No lower bound: afterDate  = 0
    - No upper bound: beforeDate = 99991231

  Private inputs:  value, key, typ
  Public inputs:   afterDate, beforeDate, fieldHash, credentialRoot
  Output:          valid
*/

component main {
    public [afterDate, beforeDate, fieldHash, credentialRoot]
} = DateRangeValidator();
