import { generateSecretKey, getPublicKey, finalizeEvent, type EventTemplate, type Event } from "nostr-tools/pure";
import { decode, nsecEncode } from "nostr-tools/nip19";
import { encrypt as nip04Encrypt, decrypt as nip04Decrypt } from "nostr-tools/nip04";
import { encrypt as nip44Encrypt, decrypt as nip44Decrypt, getConversationKey } from "nostr-tools/nip44";

export const DEFAULT_STORAGE_KEY = "nostr_passkey_identity";
export const DEFAULT_PRF_SALT_STRING = "nostr-passkey-nsec-v1";

export interface PasskeyIdentityRecord {
  version: 1;
  credentialId: string;
  encryptedNsec: string;
  pubkey: string;
}

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
  prfSalt?: Uint8Array;
  prfSaltString?: string;
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

async function getPrfSalt(options?: PasskeyIdentityOptions): Promise<Uint8Array> {
  if (options?.prfSalt) return options.prfSalt;
  const str = options?.prfSaltString || DEFAULT_PRF_SALT_STRING;
  const encoder = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(str));
  return new Uint8Array(digest);
}

function isValidRecord(value: unknown): value is PasskeyIdentityRecord {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return (
    record.version === 1 &&
    typeof record.credentialId === "string" &&
    typeof record.encryptedNsec === "string" &&
    typeof record.pubkey === "string"
  );
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
  const digest = await crypto.subtle.digest("SHA-256", prfResult);
  return new Uint8Array(digest);
}

function extractPRFResult(credential: PublicKeyCredential): ArrayBuffer | undefined {
  const extensions = credential.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
  return extensions.prf?.results?.first;
}

function parseImportedSecretKey(input: string): Uint8Array {
  const cleaned = input.trim();
  if (!cleaned) {
    throw new Error("Please provide a Nostr secret key.");
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

async function enrollPasskeyCredential(options?: PasskeyIdentityOptions): Promise<{ credentialId: string; prfKey: Uint8Array }> {
  if (!(await isPRFSupported())) {
    throw new Error("Passkeys are not supported in this browser.");
  }

  const salt = await getPrfSalt(options);
  const rpId = options?.rpId || (typeof location !== "undefined" ? location.hostname : "localhost");
  const rpName = options?.rpName || "Nostr Passkey";
  const userName = options?.userName || "nostr-identity";
  const displayName = options?.displayName || "Nostr Identity";

  const credential = (await navigator.credentials.create({
    publicKey: {
      rp: { name: rpName, id: rpId },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: userName,
        displayName: displayName,
      },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      extensions: { prf: { eval: { first: salt } } },
    },
  } as any)) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("Passkey registration was cancelled.");
  }

  let prfResult = extractPRFResult(credential);

  if (prfResult === undefined) {
    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ id: credential.rawId, type: "public-key" }],
        userVerification: "required",
        extensions: { prf: { eval: { first: salt } } },
      },
    } as any)) as PublicKeyCredential | null;

    if (assertion) {
      prfResult = extractPRFResult(assertion);
    }
  }

  if (prfResult === undefined) {
    throw new Error("This device does not support passkey-based encryption (PRF extension required).");
  }

  return {
    credentialId: arrayBufferToBase64Url(credential.rawId),
    prfKey: await normalizePRFKey(prfResult),
  };
}

async function persistPasskeyIdentity(
  secretKey: Uint8Array,
  credentialId: string,
  prfKey: Uint8Array,
  options?: PasskeyIdentityOptions
): Promise<PasskeyIdentityResult> {
  const pubkey = getPublicKey(secretKey);
  const encryptedNsec = nip44Encrypt(bytesToHex(secretKey), prfKey);
  const record: PasskeyIdentityRecord = { version: 1, credentialId, encryptedNsec, pubkey };
  const key = options?.storageKey || DEFAULT_STORAGE_KEY;
  localStorage.setItem(key, JSON.stringify(record));
  return { secretKey, pubkey, record };
}

export async function registerPasskeyIdentity(options?: PasskeyIdentityOptions): Promise<PasskeyIdentityResult> {
  const { credentialId, prfKey } = await enrollPasskeyCredential(options);
  const secretKey = generateSecretKey();
  return persistPasskeyIdentity(secretKey, credentialId, prfKey, options);
}

export async function importPasskeyIdentityFromNsec(nsec: string, options?: PasskeyIdentityOptions): Promise<PasskeyIdentityResult> {
  const secretKey = parseImportedSecretKey(nsec);
  const { credentialId, prfKey } = await enrollPasskeyCredential(options);
  return persistPasskeyIdentity(secretKey, credentialId, prfKey, options);
}

export async function unlockPasskeyIdentity(
  record?: PasskeyIdentityRecord,
  options?: PasskeyIdentityOptions
): Promise<PasskeyIdentityResult> {
  const stored = record ?? readStoredPasskeyIdentity(options);
  if (!stored) {
    throw new Error("No passkey identity found on this device.");
  }

  const salt = await getPrfSalt(options);
  const credentialIdBytes = base64UrlToArrayBuffer(stored.credentialId);
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ id: credentialIdBytes, type: "public-key" }],
      userVerification: "required",
      extensions: { prf: { eval: { first: salt } } },
    },
  } as any)) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("Passkey unlock was cancelled.");
  }

  const prfResult = extractPRFResult(credential);
  if (prfResult === undefined) {
    throw new Error("Passkey unlock failed: PRF extension result unavailable.");
  }

  const prfKey = await normalizePRFKey(prfResult);
  const nsecHex = nip44Decrypt(stored.encryptedNsec, prfKey);
  const secretKey = hexToBytes(nsecHex);

  if (getPublicKey(secretKey) !== stored.pubkey) {
    throw new Error("Passkey identity mismatch.");
  }

  return { secretKey, pubkey: stored.pubkey, record: stored };
}

export async function exportPasskeyIdentityAsNsec(
  record?: PasskeyIdentityRecord,
  options?: PasskeyIdentityOptions
): Promise<string> {
  const { secretKey } = await unlockPasskeyIdentity(record, options);
  return nsecEncode(secretKey);
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
  __nostrPasskey: true;
}

export function buildPasskeySignerShim(secretKey: Uint8Array): PasskeySignerShim {
  return {
    getPublicKey: async () => getPublicKey(secretKey),
    signEvent: async (template: EventTemplate) => finalizeEvent(template, secretKey),
    nip04: {
      encrypt: async (pubkey: string, plaintext: string) => nip04Encrypt(secretKey, pubkey, plaintext),
      decrypt: async (pubkey: string, ciphertext: string) => nip04Decrypt(secretKey, pubkey, ciphertext),
    },
    nip44: {
      encrypt: async (pubkey: string, plaintext: string) => nip44Encrypt(plaintext, getConversationKey(secretKey, pubkey)),
      decrypt: async (pubkey: string, ciphertext: string) => nip44Decrypt(ciphertext, getConversationKey(secretKey, pubkey)),
    },
    __nostrPasskey: true,
  };
}

export function isPasskeyShim(value: unknown): value is PasskeySignerShim {
  return !!value && typeof value === "object" && (value as { __nostrPasskey?: unknown }).__nostrPasskey === true;
}
