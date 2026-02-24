/**
 * ecies_salt.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * ECIES encryption for a single identity-wide salt.
 *
 * Design: one salt per identity owner, encrypted once under their public key.
 * All credential leaves share this same salt:
 *
 *   leaf = Poseidon(key, typ, value, salt)   ← salt is the same for every field
 *
 * The encrypted blob is stored once (e.g. in the credential document header).
 * Only the private key holder can decrypt it and therefore reconstruct any leaf.
 *
 * Curve  : secp256k1  (compatible with Ethereum wallets)
 * KDF    : HKDF-SHA256  with domain separation
 * Cipher : AES-256-GCM  (authenticated — detects tampering)
 *
 * Wire format (125 bytes, hex-encoded):
 *   [ephemeralPub: 65][iv: 12][ciphertext: 32][authTag: 16]
 *
 * npm install @noble/secp256k1 @noble/hashes
 */

import * as secp from "@noble/secp256k1";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes, createCipheriv, createDecipheriv } from "crypto";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/** A 32-byte random salt as a BigInt field element (fits inside BN254 prime) */
export type Salt = bigint;

/** Hex-encoded 125-byte ECIES ciphertext — stored once per identity */
export type EncryptedSalt = string;

export interface OwnerKeyPair {
  privateKey: string; // 32-byte secp256k1 private key, hex
  publicKey: string;  // 65-byte uncompressed public key, hex (04 || x || y)
}

// ─────────────────────────────────────────────────────────────────────────────
// Key utilities
// ─────────────────────────────────────────────────────────────────────────────

/** Generate a fresh secp256k1 key pair. In production, import from ETH wallet. */
export function generateOwnerKeyPair(): OwnerKeyPair {
  const priv = secp.utils.randomPrivateKey();
  const pub  = secp.getPublicKey(priv, false);
  return {
    privateKey: Buffer.from(priv).toString("hex"),
    publicKey:  Buffer.from(pub).toString("hex"),
  };
}

/** Derive uncompressed public key from a hex private key. */
export function publicKeyFromPrivate(privHex: string): string {
  return Buffer.from(secp.getPublicKey(Buffer.from(privHex, "hex"), false)).toString("hex");
}

// ─────────────────────────────────────────────────────────────────────────────
// Salt generation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate one cryptographically secure identity salt.
 * Top 3 bits masked so it always fits inside the BN254 scalar field.
 */
export function generateSalt(): Salt {
  const bytes = randomBytes(32);
  bytes[0] &= 0x1f; // 2^253 < BN254 prime
  return BigInt("0x" + bytes.toString("hex"));
}

// ─────────────────────────────────────────────────────────────────────────────
// ECIES Encrypt
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Encrypt the identity salt under the owner's public key.
 * Call once at identity issuance — store the returned hex blob in the credential doc.
 */
export async function encryptSalt(salt: Salt, ownerPubKeyHex: string): Promise<EncryptedSalt> {
  // 1. Ephemeral key pair
  const ephPriv = secp.utils.randomPrivateKey();
  const ephPub  = secp.getPublicKey(ephPriv, false); // 65 bytes

  // 2. ECDH — shared point X coordinate
  const ownerPoint  = secp.ProjectivePoint.fromHex(Buffer.from(ownerPubKeyHex, "hex"));
  const sharedPoint = ownerPoint.multiply(BigInt("0x" + Buffer.from(ephPriv).toString("hex")));
  const sharedX     = sharedPoint.toRawBytes(false).slice(1, 33); // 32 bytes

  // 3. HKDF-SHA256 → 32-byte AES key
  const aesKey = hkdf(sha256, sharedX,
    Buffer.from("zkidentity-v1"),     // salt
    Buffer.from("aes-256-gcm-key"),  // info
    32
  );

  // 4. AES-256-GCM encrypt
  const iv         = randomBytes(12);
  const saltBytes  = saltToBytes32(salt);
  const cipher     = createCipheriv("aes-256-gcm", aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(saltBytes), cipher.final()]);
  const authTag    = cipher.getAuthTag(); // 16 bytes

  // 5. Wire format: ephPub(65) || iv(12) || ciphertext(32) || authTag(16) = 125 bytes
  return Buffer.concat([Buffer.from(ephPub), iv, ciphertext, authTag]).toString("hex");
}

// ─────────────────────────────────────────────────────────────────────────────
// ECIES Decrypt
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Decrypt the identity salt using the owner's private key.
 * This is the only way to recover the salt — and therefore the only way
 * to reconstruct any Merkle leaf or generate a ZK proof.
 */
export async function decryptSalt(encryptedSalt: EncryptedSalt, ownerPrivKeyHex: string): Promise<Salt> {
  const blob = Buffer.from(encryptedSalt, "hex");
  if (blob.length !== 125) {
    throw new Error(`Invalid encrypted salt: expected 125 bytes, got ${blob.length}`);
  }

  const ephPubBytes = blob.slice(0, 65);
  const iv          = blob.slice(65, 77);
  const ciphertext  = blob.slice(77, 109);
  const authTag     = blob.slice(109, 125);

  // ECDH
  const privBigInt  = BigInt("0x" + ownerPrivKeyHex);
  const ephPoint    = secp.ProjectivePoint.fromHex(ephPubBytes);
  const sharedX     = ephPoint.multiply(privBigInt).toRawBytes(false).slice(1, 33);

  // Same KDF
  const aesKey = hkdf(sha256, sharedX,
    Buffer.from("zkidentity-v1"),
    Buffer.from("aes-256-gcm-key"),
    32
  );

  // Decrypt + verify auth tag
  const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(authTag);
  let plain: Buffer;
  try {
    plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("ECIES decryption failed: wrong private key or tampered ciphertext.");
  }

  return bytesToSalt(plain);
}

// ─────────────────────────────────────────────────────────────────────────────
// Re-encryption (key rotation)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Re-encrypt the salt under a new public key after a key rotation.
 * The Merkle root and all leaf hashes remain unchanged.
 */
export async function reEncryptSalt(
  encryptedSalt: EncryptedSalt,
  oldPrivKeyHex: string,
  newPubKeyHex: string
): Promise<EncryptedSalt> {
  const plain = await decryptSalt(encryptedSalt, oldPrivKeyHex);
  return encryptSalt(plain, newPubKeyHex);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function saltToBytes32(salt: Salt): Buffer {
  const hex = salt.toString(16).padStart(64, "0");
  if (hex.length > 64) throw new Error("Salt exceeds 32 bytes");
  return Buffer.from(hex, "hex");
}

function bytesToSalt(buf: Buffer): Salt {
  return BigInt("0x" + buf.toString("hex"));
}
