import { generateSecretKey, getPublicKey, finalizeEvent, type EventTemplate, type Event } from "nostr-tools/pure";
import { decode, nsecEncode } from "nostr-tools/nip19";
import { encrypt as nip04Encrypt, decrypt as nip04Decrypt } from "nostr-tools/nip04";
import { encrypt as nip44Encrypt, decrypt as nip44Decrypt, getConversationKey } from "nostr-tools/nip44";

export const DEFAULT_STORAGE_KEY = "nostr_passkey_identity";
export const DEFAULT_PRF_SALT_STRING = "nostr-passkey-nsec-v1";

const PRF_CONTEXT_V2 = "nostr-passkey-nsec-v2";
const AES_INFO_STRING = "nostr-passkey-aes-key";
const RECORD_SALT_BYTES = 16;
const MAX_NSEC_INPUT_LENGTH = 256;

/* ------------------------------------------------------------------ */
/*  Types                                                             */
/* ------------------------------------------------------------------ */

export interface PasskeyIdentityRecordV1 {
  version: 1;
  credentialId: string;
  encryptedNsec: string;
  pubkey: string;
}

export interface PasskeyIdentityRecordV2 {
  version: 2;
  credentialId: string;
  encryptedNsec: string;
  pubkey: string;
  salt: string;
  rpId: string;
}

export type PasskeyIdentityRecord = PasskeyIdentityRecordV1 | PasskeyIdentityRecordV2;

export interface PasskeyIdentityResult {
  secretKey: Uint8Array;
  pubkey: string;
  record: PasskeyIdentityRecord;
}

export interface PasskeyIdentityOptions {
  rpName?: string;
  rpId?: string;
  userName?: string;
  displayName?: string;
  storageKey?: string;
  /** @deprecated Only used for v1 record migration. v2 uses a per-record random salt. */
  prfSalt?: Uint8Array;
  /** @deprecated Only used for v1 record migration. v2 uses a per-record random salt. */
  prfSaltString?: string;
}

export interface PasskeySignerShim {
  getPublicKey: () => Promise<string>;
  signEvent: (template: EventTemplate) => Promise<Event>;
  nip04: {
    encrypt: (pubkey: string, plaintext: string) => Promise<string>;
    decrypt: (pubkey: string, ciphertext: string) => Promise<string>;
  };
  nip44: {
    encrypt: (pubkey: string, plaintext: string) => Promise<string>;
    decrypt: (pubkey: string, ciphertext: string) => Promise<string>;
  };
  destroy: () => void;
  __nostrPasskey: true;
}

/* Internal PRF extension types (not in standard TS lib) */
interface PRFValues {
  first: BufferSource;
  second?: BufferSource;
}

interface PRFExtensionEval {
  eval: PRFValues;
}

interface PRFResults {
  prf?: {
    results?: {
      first?: ArrayBuffer;
      second?: ArrayBuffer;
    };
  };
}

/* ------------------------------------------------------------------ */
/*  Helpers – encoding / decoding / crypto                            */
/* ------------------------------------------------------------------ */

function asBuffer(data: Uint8Array): BufferSource {
  return new Uint8Array(data.buffer as ArrayBuffer, data.byteOffset, data.byteLength);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function zeroBytes(bytes: Uint8Array): void {
  bytes.fill(0);
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a);
  result.set(b, a.length);
  return result;
}

async function sha256(data: BufferSource): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToArrayBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + padding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/* ------------------------------------------------------------------ */
/*  v1 PRF salt (kept for migration)                                  */
/* ------------------------------------------------------------------ */

async function getPrfSalt(options?: PasskeyIdentityOptions): Promise<Uint8Array> {
  if (options?.prfSalt) return options.prfSalt;
  const str = options?.prfSaltString || DEFAULT_PRF_SALT_STRING;
  return sha256(asBuffer(new TextEncoder().encode(str)));
}

/* ------------------------------------------------------------------ */
/*  AES-GCM encryption / decryption for storage (v2)                  */
/* ------------------------------------------------------------------ */

async function deriveAESKey(prfOutput: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey("raw", asBuffer(prfOutput), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt: asBuffer(salt),
      info: asBuffer(new TextEncoder().encode(AES_INFO_STRING)),
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function aesGcmEncrypt(plaintext: string, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: asBuffer(iv) }, key, asBuffer(encoded)));
  const combined = new Uint8Array(iv.length + ciphertext.length);
  combined.set(iv);
  combined.set(ciphertext, iv.length);
  return arrayBufferToBase64Url(combined.buffer as ArrayBuffer);
}

async function aesGcmDecrypt(encoded: string, key: CryptoKey): Promise<string> {
  const combined = new Uint8Array(base64UrlToArrayBuffer(encoded));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asBuffer(iv) }, key, asBuffer(ciphertext));
  return new TextDecoder().decode(decrypted);
}

/* ------------------------------------------------------------------ */
/*  Record validation / storage                                       */
/* ------------------------------------------------------------------ */

function isValidRecord(value: unknown): value is PasskeyIdentityRecord {
  if (!value || typeof value !== "object") return false;
  const rec = value as Record<string, unknown>;
  if (rec.version === 1) {
    return (
      typeof rec.credentialId === "string" &&
      typeof rec.encryptedNsec === "string" &&
      typeof rec.pubkey === "string"
    );
  }
  if (rec.version === 2) {
    return (
      typeof rec.credentialId === "string" &&
      rec.credentialId.length > 0 &&
      typeof rec.encryptedNsec === "string" &&
      rec.encryptedNsec.length > 0 &&
      typeof rec.pubkey === "string" &&
      /^[0-9a-fA-F]{64}$/.test(rec.pubkey as string) &&
      typeof rec.salt === "string" &&
      rec.salt.length > 0 &&
      typeof rec.rpId === "string" &&
      rec.rpId.length > 0
    );
  }
  return false;
}

export function readStoredPasskeyIdentity(options?: PasskeyIdentityOptions): PasskeyIdentityRecord | null {
  if (typeof window === "undefined") return null;
  const key = options?.storageKey || DEFAULT_STORAGE_KEY;
  const stored = localStorage.getItem(key);
  if (!stored) return null;
  try {
    const parsed = JSON.parse(stored);
    return isValidRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function hasStoredPasskeyIdentity(options?: PasskeyIdentityOptions): boolean {
  return readStoredPasskeyIdentity(options) !== null;
}

export function getStoredPasskeyPubkey(options?: PasskeyIdentityOptions): string | null {
  const record = readStoredPasskeyIdentity(options);
  return record ? record.pubkey : null;
}

export function clearPasskeyIdentity(options?: PasskeyIdentityOptions): void {
  if (typeof window !== "undefined") {
    const key = options?.storageKey || DEFAULT_STORAGE_KEY;
    localStorage.removeItem(key);
  }
}

/* ------------------------------------------------------------------ */
/*  WebAuthn support & PRF helpers                                    */
/* ------------------------------------------------------------------ */

export async function isPRFSupported(): Promise<boolean> {
  return (
    typeof window !== "undefined" &&
    !!window.PublicKeyCredential &&
    typeof navigator?.credentials?.create === "function"
  );
}

async function normalizePRFKey(prfResult: ArrayBuffer): Promise<Uint8Array> {
  if (prfResult.byteLength === 32) {
    return new Uint8Array(prfResult);
  }
  return sha256(new Uint8Array(prfResult));
}

function extractPRFResults(credential: PublicKeyCredential): { first?: ArrayBuffer; second?: ArrayBuffer } | undefined {
  const extensions = credential.getClientExtensionResults() as PRFResults;
  return extensions.prf?.results;
}

/* ------------------------------------------------------------------ */
/*  Secret key parsing                                                */
/* ------------------------------------------------------------------ */

function parseImportedSecretKey(input: string): Uint8Array {
  const cleaned = input.trim();
  if (!cleaned) {
    throw new Error("Please provide a Nostr secret key.");
  }
  if (cleaned.length > MAX_NSEC_INPUT_LENGTH) {
    throw new Error("Input exceeds maximum length.");
  }
  if (/^[0-9a-fA-F]{64}$/.test(cleaned)) {
    return hexToBytes(cleaned);
  }
  const decoded = decode(cleaned);
  if (decoded.type === "nsec") {
    return decoded.data;
  }
  throw new Error("Please provide a valid nsec or 64-character hex secret key.");
}

/* ------------------------------------------------------------------ */
/*  Enrollment (v2 only — new records are always v2)                  */
/* ------------------------------------------------------------------ */

async function computePRFInputV2(recordSalt: Uint8Array): Promise<Uint8Array> {
  return sha256(asBuffer(concatBytes(recordSalt, new TextEncoder().encode(PRF_CONTEXT_V2))));
}

async function enrollPasskeyCredential(options?: PasskeyIdentityOptions): Promise<{
  credentialId: string;
  prfKey: Uint8Array;
  salt: Uint8Array;
}> {
  if (!(await isPRFSupported())) {
    throw new Error("Passkeys are not supported in this browser.");
  }

  const recordSalt = crypto.getRandomValues(new Uint8Array(RECORD_SALT_BYTES));
  const prfInput = await computePRFInputV2(recordSalt);
  const rpId = options?.rpId || (typeof location !== "undefined" ? location.hostname : "localhost");
  const rpName = options?.rpName || "Nostr Passkey";
  const userName = options?.userName || "nostr-identity";
  const displayName = options?.displayName || "Nostr Identity";

  const credential = (await navigator.credentials.create({
    publicKey: {
      rp: { name: rpName, id: rpId },
      user: {
        id: asBuffer(crypto.getRandomValues(new Uint8Array(16))),
        name: userName,
        displayName,
      },
      challenge: asBuffer(crypto.getRandomValues(new Uint8Array(32))),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      extensions: { prf: { eval: { first: asBuffer(prfInput) } } },
    },
  } as CredentialCreationOptions)) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("Passkey registration was cancelled.");
  }

  let results = extractPRFResults(credential);

  if (!results?.first) {
    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: asBuffer(crypto.getRandomValues(new Uint8Array(32))),
        rpId,
        allowCredentials: [{ id: credential.rawId, type: "public-key" }],
        userVerification: "required",
        extensions: { prf: { eval: { first: asBuffer(prfInput) } } },
      },
    } as CredentialRequestOptions)) as PublicKeyCredential | null;
    if (assertion) {
      results = extractPRFResults(assertion);
    }
  }

  if (!results?.first) {
    throw new Error("This device does not support passkey-based encryption (PRF extension required).");
  }

  return {
    credentialId: arrayBufferToBase64Url(credential.rawId),
    prfKey: await normalizePRFKey(results.first),
    salt: recordSalt,
  };
}

/* ------------------------------------------------------------------ */
/*  Persist identity (v2)                                             */
/* ------------------------------------------------------------------ */

async function persistPasskeyIdentityV2(
  secretKey: Uint8Array,
  credentialId: string,
  prfKey: Uint8Array,
  salt: Uint8Array,
  options?: PasskeyIdentityOptions
): Promise<PasskeyIdentityResult> {
  const pubkey = getPublicKey(secretKey);
  const aesKey = await deriveAESKey(prfKey, salt);
  const encryptedNsec = await aesGcmEncrypt(bytesToHex(secretKey), aesKey);
  const rpId = options?.rpId || (typeof location !== "undefined" ? location.hostname : "localhost");
  const record: PasskeyIdentityRecordV2 = {
    version: 2,
    credentialId,
    encryptedNsec,
    pubkey,
    salt: arrayBufferToBase64Url(salt.buffer as ArrayBuffer),
    rpId,
  };
  const key = options?.storageKey || DEFAULT_STORAGE_KEY;
  localStorage.setItem(key, JSON.stringify(record));
  return { secretKey, pubkey, record };
}

/* ------------------------------------------------------------------ */
/*  Public registration / import                                      */
/* ------------------------------------------------------------------ */

export async function registerPasskeyIdentity(options?: PasskeyIdentityOptions): Promise<PasskeyIdentityResult> {
  const { credentialId, prfKey, salt } = await enrollPasskeyCredential(options);
  const secretKey = generateSecretKey();
  return persistPasskeyIdentityV2(secretKey, credentialId, prfKey, salt, options);
}

export async function importPasskeyIdentityFromNsec(nsec: string, options?: PasskeyIdentityOptions): Promise<PasskeyIdentityResult> {
  const secretKey = parseImportedSecretKey(nsec);
  const { credentialId, prfKey, salt } = await enrollPasskeyCredential(options);
  return persistPasskeyIdentityV2(secretKey, credentialId, prfKey, salt, options);
}

/* ------------------------------------------------------------------ */
/*  Unlock                                                            */
/* ------------------------------------------------------------------ */

async function unlockV1(
  stored: PasskeyIdentityRecordV1,
  options?: PasskeyIdentityOptions
): Promise<PasskeyIdentityResult> {
  const oldPrfInput = await getPrfSalt(options);
  const credentialIdBytes = base64UrlToArrayBuffer(stored.credentialId);
  const rpId = options?.rpId || (typeof location !== "undefined" ? location.hostname : "localhost");

  const newRecordSalt = crypto.getRandomValues(new Uint8Array(RECORD_SALT_BYTES));
  const newPrfInput = await computePRFInputV2(newRecordSalt);

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: asBuffer(crypto.getRandomValues(new Uint8Array(32))),
      rpId,
      allowCredentials: [{ id: credentialIdBytes, type: "public-key" }],
      userVerification: "required",
      extensions: { prf: { eval: { first: asBuffer(oldPrfInput), second: asBuffer(newPrfInput) } } },
    },
  } as CredentialRequestOptions)) as PublicKeyCredential | null;

  if (!credential) throw new Error("Passkey unlock was cancelled.");

  const results = extractPRFResults(credential);
  if (!results?.first) throw new Error("Operation failed.");

  const oldPrfKey = await normalizePRFKey(results.first);
  const nsecHex = nip44Decrypt(stored.encryptedNsec, oldPrfKey);
  const secretKey = hexToBytes(nsecHex);

  if (getPublicKey(secretKey) !== stored.pubkey) {
    throw new Error("Passkey identity mismatch.");
  }

  if (results.second) {
    const newPrfKey = await normalizePRFKey(results.second);
    const aesKey = await deriveAESKey(newPrfKey, newRecordSalt);
    const encryptedNsec = await aesGcmEncrypt(nsecHex, aesKey);
    const v2Record: PasskeyIdentityRecordV2 = {
      version: 2,
      credentialId: stored.credentialId,
      encryptedNsec,
      pubkey: stored.pubkey,
      salt: arrayBufferToBase64Url(newRecordSalt.buffer as ArrayBuffer),
      rpId,
    };
    const key = options?.storageKey || DEFAULT_STORAGE_KEY;
    localStorage.setItem(key, JSON.stringify(v2Record));
    return { secretKey, pubkey: stored.pubkey, record: v2Record };
  }

  return { secretKey, pubkey: stored.pubkey, record: stored };
}

async function unlockV2(
  stored: PasskeyIdentityRecordV2,
  _options?: PasskeyIdentityOptions
): Promise<PasskeyIdentityResult> {
  const recordSalt = new Uint8Array(base64UrlToArrayBuffer(stored.salt));
  const prfInput = await computePRFInputV2(recordSalt);
  const credentialIdBytes = base64UrlToArrayBuffer(stored.credentialId);
  const rpId = stored.rpId;

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: asBuffer(crypto.getRandomValues(new Uint8Array(32))),
      rpId,
      allowCredentials: [{ id: credentialIdBytes, type: "public-key" }],
      userVerification: "required",
      extensions: { prf: { eval: { first: asBuffer(prfInput) } } },
    },
  } as CredentialRequestOptions)) as PublicKeyCredential | null;

  if (!credential) throw new Error("Passkey unlock was cancelled.");

  const results = extractPRFResults(credential);
  if (!results?.first) throw new Error("Operation failed.");

  const prfKey = await normalizePRFKey(results.first);
  const aesKey = await deriveAESKey(prfKey, recordSalt);
  const nsecHex = await aesGcmDecrypt(stored.encryptedNsec, aesKey);
  const secretKey = hexToBytes(nsecHex);

  if (getPublicKey(secretKey) !== stored.pubkey) {
    throw new Error("Passkey identity mismatch.");
  }

  return { secretKey, pubkey: stored.pubkey, record: stored };
}

export async function unlockPasskeyIdentity(
  record?: PasskeyIdentityRecord,
  options?: PasskeyIdentityOptions
): Promise<PasskeyIdentityResult> {
  const stored = record ?? readStoredPasskeyIdentity(options);
  if (!stored) {
    throw new Error("No passkey identity found on this device.");
  }
  if (stored.version === 1) {
    return unlockV1(stored, options);
  }
  return unlockV2(stored, options);
}

/* ------------------------------------------------------------------ */
/*  Export                                                            */
/* ------------------------------------------------------------------ */

export async function exportPasskeyIdentityAsNsec(
  record?: PasskeyIdentityRecord,
  options?: PasskeyIdentityOptions
): Promise<string> {
  const { secretKey } = await unlockPasskeyIdentity(record, options);
  return nsecEncode(secretKey);
}

/* ------------------------------------------------------------------ */
/*  NIP-07 signer shim                                                */
/* ------------------------------------------------------------------ */

export function buildPasskeySignerShim(secretKey: Uint8Array): PasskeySignerShim {
  let destroyed = false;
  const requireAlive = (): void => {
    if (destroyed) throw new Error("Signer has been destroyed.");
  };
  return {
    getPublicKey: async () => {
      requireAlive();
      return getPublicKey(secretKey);
    },
    signEvent: async (template: EventTemplate) => {
      requireAlive();
      return finalizeEvent(template, secretKey);
    },
    nip04: {
      encrypt: async (pubkey: string, plaintext: string) => {
        requireAlive();
        return nip04Encrypt(secretKey, pubkey, plaintext);
      },
      decrypt: async (pubkey: string, ciphertext: string) => {
        requireAlive();
        return nip04Decrypt(secretKey, pubkey, ciphertext);
      },
    },
    nip44: {
      encrypt: async (pubkey: string, plaintext: string) => {
        requireAlive();
        return nip44Encrypt(plaintext, getConversationKey(secretKey, pubkey));
      },
      decrypt: async (pubkey: string, ciphertext: string) => {
        requireAlive();
        return nip44Decrypt(ciphertext, getConversationKey(secretKey, pubkey));
      },
    },
    destroy: () => {
      zeroBytes(secretKey);
      destroyed = true;
    },
    __nostrPasskey: true,
  };
}

/* ------------------------------------------------------------------ */
/*  Type guard                                                        */
/* ------------------------------------------------------------------ */

export function isPasskeyShim(value: unknown): value is PasskeySignerShim {
  return !!value && typeof value === "object" && (value as { __nostrPasskey?: unknown }).__nostrPasskey === true;
}
