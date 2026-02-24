/**
 * identity_tree.ts  (v3 — single shared salt per identity)
 * ─────────────────────────────────────────────────────────────────────────────
 * One ECIES-encrypted salt per identity owner.
 * All leaves share the same salt: Poseidon(key, typ, value, salt)
 *
 * The encrypted blob is stored once in the credential document.
 * No SaltStore. No per-field index tracking.
 *
 * npm install circomlibjs @noble/secp256k1 @noble/hashes snarkjs
 */

import { buildPoseidon } from "circomlibjs";
import * as fs from "fs";
import {
  Salt,
  EncryptedSalt,
  OwnerKeyPair,
  generateOwnerKeyPair,
  generateSalt,
  encryptSalt,
  decryptSalt,
  reEncryptSalt,
} from "./ecies_salt";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type FieldElement = bigint;

export const CredentialType = {
  TEXT: 0n,
  EMAIL: 1n,
  NUMBER: 2n,
  DATE: 3n,
  ATTACHMENT: 4n,
  LONG_TEXT: 5n,
} as const;

/** A credential field. No salt — salt is identity-level, shared across all fields. */
export interface CredentialField {
  key: FieldElement;    // Numeric label identifier
  typ: FieldElement;    // CredentialType value
  value: FieldElement;  // The credential value
}

export interface ProofInput {
  // Private — stays on the owner's device
  key: string;
  typ: string;
  value: string;
  salt: string;
  pathElements: string[];
  pathIndices: number[];
  identitySecret: string;
  // Public — shared with verifier
  credentialRoot: string;
  walletAddress: string;
  threshold: string;
  expectedValueHash: string;
}

/**
 * Serialisable credential document — everything the issuer produces.
 * The `encryptedSalt` is the only sensitive field; the rest is public.
 */
export interface CredentialDocument {
  ownerPubKey: string;
  encryptedSalt: EncryptedSalt; // 125-byte ECIES blob, hex-encoded
  credentialRoot: string;
  leaves: Array<{ index: number; leaf: string; field: { key: string; typ: string; value: string } }>;
  issuedAt: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Poseidon singleton
// ─────────────────────────────────────────────────────────────────────────────

class PoseidonHasher {
  private poseidon: any = null;
  private F: any = null;

  async init() {
    if (!this.poseidon) {
      this.poseidon = await buildPoseidon();
      this.F = this.poseidon.F;
    }
  }

  hash(inputs: FieldElement[]): FieldElement {
    if (!this.poseidon) throw new Error("Call init() first");
    return this.F.toObject(this.poseidon(inputs.map((x) => this.F.e(x)))) as bigint;
  }
}

export const poseidonHasher = new PoseidonHasher();

// ─────────────────────────────────────────────────────────────────────────────
// Encoding helpers
// ─────────────────────────────────────────────────────────────────────────────

export function stringToField(input: string): FieldElement {
  const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const bytes = Buffer.from(input, "utf8");
  if (bytes.length <= 30) {
    return BigInt("0x" + bytes.toString("hex")) % BN254_PRIME;
  }
  const { createHash } = require("crypto");
  const digest: Buffer = createHash("sha256").update(bytes).digest();
  digest[0] &= 0x1f; // 253-bit truncation
  return BigInt("0x" + digest.toString("hex")) % BN254_PRIME;
}

export function dateToField(dateStr: string): FieldElement {
  const clean = dateStr.replace(/-/g, "");
  if (!/^\d{8}$/.test(clean)) throw new Error(`Invalid date: ${dateStr}`);
  return BigInt(clean);
}

export async function deriveWalletAddress(identitySecret: FieldElement): Promise<FieldElement> {
  await poseidonHasher.init();
  return poseidonHasher.hash([identitySecret]);
}

// ─────────────────────────────────────────────────────────────────────────────
// IdentityMerkleTree
// ─────────────────────────────────────────────────────────────────────────────

const TREE_DEPTH = 8;
const TREE_SIZE  = 2 ** TREE_DEPTH; // 256

export class IdentityMerkleTree {
  private leaves: FieldElement[] = [];
  private zeroLeaf!: FieldElement;
  private layers: FieldElement[][] = [];

  // The single encrypted salt blob — stored in the credential document header.
  // Decrypted once by the owner when generating any proof.
  private encryptedSalt!: EncryptedSalt;

  // Plaintext salt available only during the issuer build phase (then cleared).
  private _plaintextSalt: Salt | null = null;

  // Metadata for the credential document
  private leafMeta: CredentialDocument["leaves"] = [];

  private readonly ownerPubKey: string;
  private ready = false;

  constructor(ownerPubKey: string) {
    this.ownerPubKey = ownerPubKey;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ISSUER PHASE 1: initialise (generates + encrypts the single salt)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Initialise the tree and generate the identity salt.
   * The salt is encrypted immediately under `ownerPubKey` and the plaintext
   * is held in memory only for the duration of `setLeaf()` calls.
   * Call `sealTree()` when done inserting leaves — this clears the plaintext.
   */
  async init() {
    await poseidonHasher.init();

    this.zeroLeaf = poseidonHasher.hash([0n, 0n, 0n, 0n]);
    this.leaves   = new Array(TREE_SIZE).fill(this.zeroLeaf);

    // Generate one salt for the entire identity
    this._plaintextSalt = generateSalt();
    this.encryptedSalt  = await encryptSalt(this._plaintextSalt, this.ownerPubKey);

    this.ready = true;
    console.log("✅ Salt generated and encrypted. Plaintext held in memory until sealTree().");
  }

  private assertReady() {
    if (!this.ready) throw new Error("Call init() first");
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ISSUER PHASE 2: insert leaves
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Insert a credential field at `index`.
   * Uses the single identity salt — no per-field salt generation needed.
   *
   *   leaf = Poseidon(key, typ, value, identitySalt)
   */
  setLeaf(index: number, field: CredentialField): FieldElement {
    this.assertReady();
    if (this._plaintextSalt === null) {
      throw new Error("Tree is sealed — no new leaves can be inserted after sealTree().");
    }
    if (index < 0 || index >= TREE_SIZE) {
      throw new Error(`Index ${index} out of range [0, ${TREE_SIZE - 1}]`);
    }

    const leaf = poseidonHasher.hash([
      field.key,
      field.typ,
      field.value,
      this._plaintextSalt,
    ]);

    this.leaves[index] = leaf;
    this.leafMeta.push({
      index,
      leaf: leaf.toString(),
      field: {
        key:   field.key.toString(),
        typ:   field.typ.toString(),
        value: field.value.toString(),
      },
    });

    return leaf;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ISSUER PHASE 3: build tree, then seal (clears plaintext salt from memory)
  // ─────────────────────────────────────────────────────────────────────────

  buildTree(): FieldElement {
    this.assertReady();
    this.layers = [this.leaves.slice()];
    let current = this.leaves.slice();

    for (let d = 0; d < TREE_DEPTH; d++) {
      const next: FieldElement[] = [];
      for (let i = 0; i < current.length; i += 2) {
        next.push(poseidonHasher.hash([current[i], current[i + 1]]));
      }
      this.layers.push(next);
      current = next;
    }

    return current[0];
  }

  /**
   * Seal the tree — zeros out the plaintext salt from memory.
   * Must be called after `buildTree()`. No new leaves can be inserted after this.
   * The issuer can now safely hand the CredentialDocument to the owner.
   */
  sealTree() {
    this._plaintextSalt = null;
    console.log("🔒 Tree sealed — plaintext salt cleared from memory.");
  }

  get root(): FieldElement {
    if (this.layers.length === 0) throw new Error("Call buildTree() first");
    return this.layers[TREE_DEPTH][0];
  }

  get zeroLeafValue(): FieldElement { return this.zeroLeaf; }

  // ─────────────────────────────────────────────────────────────────────────
  // Credential document (issuer → owner handoff artifact)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Export the full credential document.
   * Contains the encrypted salt blob, the Merkle root, and leaf metadata.
   * This is what the issuer gives to the owner at the end of issuance.
   */
  exportCredentialDocument(): CredentialDocument {
    if (this.layers.length === 0) throw new Error("Call buildTree() first");
    return {
      ownerPubKey:   this.ownerPubKey,
      encryptedSalt: this.encryptedSalt,
      credentialRoot: this.root.toString(),
      leaves: this.leafMeta,
      issuedAt: new Date().toISOString(),
    };
  }

  saveCredentialDocument(filePath: string) {
    const doc = this.exportCredentialDocument();
    fs.writeFileSync(filePath, JSON.stringify(doc, null, 2));
    console.log(`📄 Credential document saved → ${filePath}`);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Merkle proof path
  // ─────────────────────────────────────────────────────────────────────────

  generateMerkleProof(index: number): { pathElements: FieldElement[]; pathIndices: number[] } {
    if (this.layers.length === 0) throw new Error("Call buildTree() first");

    const pathElements: FieldElement[] = [];
    const pathIndices: number[] = [];
    let cur = index;

    for (let d = 0; d < TREE_DEPTH; d++) {
      const isRight = cur % 2 === 1;
      pathIndices.push(isRight ? 1 : 0);
      pathElements.push(this.layers[d][isRight ? cur - 1 : cur + 1]);
      cur = Math.floor(cur / 2);
    }

    return { pathElements, pathIndices };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // OWNER PHASE: generate snarkjs proof input
  //
  // The owner loads their credential document, decrypts the salt once,
  // and generates the input for any field they want to prove.
  // Everything stays on their device.
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Restore a tree instance from a saved credential document.
   * Used by the owner-side — the owner has the document but not the live tree.
   */
  static async fromCredentialDocument(doc: CredentialDocument): Promise<IdentityMerkleTree> {
    const tree = new IdentityMerkleTree(doc.ownerPubKey);
    await poseidonHasher.init();

    tree.zeroLeaf      = poseidonHasher.hash([0n, 0n, 0n, 0n]);
    tree.leaves        = new Array(TREE_SIZE).fill(tree.zeroLeaf);
    tree.encryptedSalt = doc.encryptedSalt;
    tree.leafMeta      = doc.leaves;

    // Restore leaves from document metadata
    for (const entry of doc.leaves) {
      tree.leaves[entry.index] = BigInt(entry.leaf);
    }

    // Rebuild all layers so Merkle proofs work
    tree.layers = [tree.leaves.slice()];
    let current = tree.leaves.slice();
    for (let d = 0; d < TREE_DEPTH; d++) {
      const next: FieldElement[] = [];
      for (let i = 0; i < current.length; i += 2) {
        next.push(poseidonHasher.hash([current[i], current[i + 1]]));
      }
      tree.layers.push(next);
      current = next;
    }

    // Verify restored root matches the document
    const restoredRoot = current[0].toString();
    if (restoredRoot !== doc.credentialRoot) {
      throw new Error(
        `Root mismatch after restore: got ${restoredRoot}, document says ${doc.credentialRoot}. ` +
        `Credential document may be corrupted.`
      );
    }

    tree.ready = true;
    console.log(`✅ Tree restored from credential document. Root verified: ${restoredRoot.slice(0, 20)}...`);
    return tree;
  }

  /**
   * Generate the snarkjs input.json for a specific credential field.
   *
   * ⚠️  Requires the owner's private key — call on the owner's device only.
   *     The returned object contains the plaintext salt — never log or transmit it.
   *
   * @param leafIndex       The leaf to prove
   * @param field           The credential field (must match what was issued)
   * @param ownerPrivKey    Owner's secp256k1 private key hex — device-local
   * @param identitySecret  Owner's Poseidon identity binding secret
   * @param walletAddress   Poseidon(identitySecret) — public commitment
   * @param threshold       For NUMBER/DATE claims; 0n if unused
   * @param expectedValueHash  For TEXT/EMAIL/ATTACHMENT claims; 0n if unused
   */
  async generateSnarkInput(params: {
    leafIndex: number;
    field: CredentialField;
    ownerPrivKey: string;
    identitySecret: FieldElement;
    walletAddress: FieldElement;
    threshold?: FieldElement;
    expectedValueHash?: FieldElement;
  }): Promise<ProofInput> {
    this.assertReady();
    if (this.layers.length === 0) throw new Error("Call buildTree() / restore first");

    const {
      leafIndex, field, ownerPrivKey, identitySecret, walletAddress,
      threshold = 0n, expectedValueHash = 0n,
    } = params;

    // Decrypt the single identity salt (requires private key)
    const salt = await decryptSalt(this.encryptedSalt, ownerPrivKey);

    // Sanity-check: recompute leaf and verify against stored value
    const recomputed = poseidonHasher.hash([field.key, field.typ, field.value, salt]);
    if (recomputed !== this.leaves[leafIndex]) {
      throw new Error(
        `Leaf mismatch at index ${leafIndex}. ` +
        `Check that the field values match what was issued, and that the correct private key was used.`
      );
    }

    // Generate Merkle sibling path
    const { pathElements, pathIndices } = this.generateMerkleProof(leafIndex);

    return {
      key:            field.key.toString(),
      typ:            field.typ.toString(),
      value:          field.value.toString(),
      salt:           salt.toString(),       // ⚠️ private — stays on device
      pathElements:   pathElements.map((x) => x.toString()),
      pathIndices,
      identitySecret: identitySecret.toString(),
      credentialRoot: this.root.toString(),
      walletAddress:  walletAddress.toString(),
      threshold:      threshold.toString(),
      expectedValueHash: expectedValueHash.toString(),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Key rotation
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Re-encrypt the identity salt under a new public key.
   * Updates the credential document's encryptedSalt in place.
   * The Merkle root and all leaf hashes are completely unaffected.
   */
  async rotateKey(oldPrivKey: string, newPubKey: string) {
    this.encryptedSalt = await reEncryptSalt(this.encryptedSalt, oldPrivKey, newPubKey);
    console.log("✅ Salt re-encrypted under new public key. Merkle root unchanged.");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo
// ─────────────────────────────────────────────────────────────────────────────

async function demo() {
  console.log("━━━ ZK-Identity: Single ECIES Salt Demo ━━━\n");

  // ── Owner generates key pair ─────────────────────────────────────────────
  const ownerKeys: OwnerKeyPair = generateOwnerKeyPair();
  console.log("Owner pubKey:", ownerKeys.publicKey.slice(0, 20) + "...");

  // ── ISSUER PHASE ─────────────────────────────────────────────────────────
  console.log("\n── Issuer Phase ──");
  const tree = new IdentityMerkleTree(ownerKeys.publicKey);
  await tree.init(); // generates + encrypts ONE salt

  const fields: Array<{ index: number; field: CredentialField }> = [
    { index: 0, field: { key: stringToField("name"),  typ: CredentialType.TEXT,   value: stringToField("Alice") } },
    { index: 1, field: { key: stringToField("email"), typ: CredentialType.EMAIL,  value: stringToField("alice@example.com") } },
    { index: 2, field: { key: stringToField("dob"),   typ: CredentialType.DATE,   value: dateToField("1999-03-15") } },
    { index: 3, field: { key: stringToField("score"), typ: CredentialType.NUMBER, value: 720n } },
  ];

  for (const { index, field } of fields) {
    const leaf = tree.setLeaf(index, field); // synchronous — salt already in memory
    console.log(`  Leaf[${index}] = ${leaf.toString().slice(0, 30)}...`);
  }

  const root = tree.buildTree();
  tree.sealTree(); // clears plaintext salt from memory
  console.log(`  Merkle Root: ${root.toString().slice(0, 30)}...`);

  // Issuer hands this document to the owner
  tree.saveCredentialDocument("credential.json");

  // ── OWNER PHASE ───────────────────────────────────────────────────────────
  console.log("\n── Owner Phase ──");

  // Owner loads the credential document (no live tree object needed)
  const doc: CredentialDocument = JSON.parse(fs.readFileSync("credential.json", "utf8"));
  const ownerTree = await IdentityMerkleTree.fromCredentialDocument(doc);

  const identitySecret = 0xabcdef1234567890abcdef1234567890n;
  const walletAddress  = await deriveWalletAddress(identitySecret);

  // Prove DOB >= threshold (age check)
  const ageInput = await ownerTree.generateSnarkInput({
    leafIndex: 2,
    field: fields[2].field,
    ownerPrivKey: ownerKeys.privateKey,
    identitySecret,
    walletAddress,
    threshold: 19000101n,
    expectedValueHash: 0n,
  });
  fs.writeFileSync("input_age.json", JSON.stringify(ageInput, null, 2));
  console.log("  Age proof → input_age.json");
  console.log("  Public: threshold =", ageInput.threshold, "| root =", ageInput.credentialRoot.slice(0, 20) + "...");

  // Prove email matches a known hash
  const emailHash = poseidonHasher.hash([fields[1].field.value]);
  const emailInput = await ownerTree.generateSnarkInput({
    leafIndex: 1,
    field: fields[1].field,
    ownerPrivKey: ownerKeys.privateKey,
    identitySecret,
    walletAddress,
    threshold: 0n,
    expectedValueHash: emailHash,
  });
  fs.writeFileSync("input_email.json", JSON.stringify(emailInput, null, 2));
  console.log("  Email proof → input_email.json");
  console.log("  Public: expectedValueHash =", emailInput.expectedValueHash.slice(0, 20) + "...");

  console.log("\n━━━ Done ━━━");
  console.log("Run: snarkjs groth16 fullProve input_age.json circuit_js/circuit.wasm circuit_final.zkey");
}

demo().catch(console.error);
