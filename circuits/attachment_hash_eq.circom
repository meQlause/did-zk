pragma circom 2.0.0;

include "validators.circom";

/*
  attachment_hash_eq.circom
  ──────────────────────────
  Entry point: AttachmentFileValidator
  Type:   Attachment File (4)
  Proves: stored_doc_hash == expectedDocHash  (direct equality)
  The field value IS the document hash — no secondary hashing applied.

  Private inputs:  value, key, typ
  Public inputs:   expectedDocHash, fieldHash, credentialRoot
  Output:          valid
*/

component main {
    public [expectedDocHash, fieldHash, credentialRoot]
} = AttachmentFileValidator();
