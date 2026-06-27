import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  PasskeySigner,
  PasskeyAccount,
  isPasskeyAccount,
  getStoredPasskeyAccount,
  hasPasskeyIdentityOnDevice,
} from "./applesauce.js";

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => { store[key] = value; },
    removeItem: (key: string) => { delete store[key]; },
    clear: () => { store = {}; },
  };
})();

Object.defineProperty(globalThis, "localStorage", { value: localStorageMock, writable: true });
Object.defineProperty(globalThis, "window", { value: globalThis, writable: true });

import { webcrypto } from "node:crypto";
if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, writable: true });
}

Object.defineProperty(globalThis, "location", { value: { hostname: "localhost" }, writable: true });

function setupCredentialsMock() {
  const mockCredentials = { create: vi.fn(), get: vi.fn() };
  Object.defineProperty(globalThis, "navigator", {
    value: { credentials: mockCredentials },
    configurable: true,
    writable: true,
  });
  Object.defineProperty(globalThis, "PublicKeyCredential", {
    value: class {},
    configurable: true,
    writable: true,
  });
  return mockCredentials;
}

const PRF_KEY = new Uint8Array(32).fill(42);

function mockCreate(credentials: any, rawId?: Uint8Array) {
  credentials.create.mockResolvedValue({
    rawId: (rawId ?? new Uint8Array([1, 2, 3])).buffer,
    getClientExtensionResults: () => ({
      prf: { results: { first: PRF_KEY.buffer } },
    }),
  });
}

function mockGet(credentials: any) {
  credentials.get.mockResolvedValue({
    getClientExtensionResults: () => ({
      prf: { results: { first: PRF_KEY.buffer } },
    }),
  });
}

describe("PasskeySigner", () => {
  let credentials: ReturnType<typeof setupCredentialsMock>;

  beforeEach(() => {
    localStorageMock.clear();
    vi.restoreAllMocks();
    credentials = setupCredentialsMock();
  });

  it("constructs with options bag (locked)", () => {
    const record = {
      version: 2 as const,
      credentialId: "abc",
      encryptedNsec: "def",
      pubkey: "0".repeat(64),
      salt: "ghi",
      rpId: "localhost",
    };
    const signer = new PasskeySigner(record, {});
    expect(signer.unlocked).toBe(false);
    expect(signer.key).toBeNull();
  });

  it("constructs with pre-decrypted key (unlocked)", () => {
    const record = {
      version: 2 as const,
      credentialId: "abc",
      encryptedNsec: "def",
      pubkey: "0".repeat(64),
      salt: "ghi",
      rpId: "localhost",
    };
    const key = new Uint8Array(32).fill(7);
    const signer = new PasskeySigner(record, { key });
    expect(signer.unlocked).toBe(true);
    expect(signer.key).toBe(key);
  });

  it("schedules auto-lock when key and autoLockTimeoutMs provided", async () => {
    vi.useFakeTimers();
    const record = {
      version: 2 as const,
      credentialId: "abc",
      encryptedNsec: "def",
      pubkey: "0".repeat(64),
      salt: "ghi",
      rpId: "localhost",
    };
    const key = new Uint8Array(32).fill(7);
    const signer = new PasskeySigner(record, { key, autoLockTimeoutMs: 500 });
    expect(signer.unlocked).toBe(true);

    // Advance time past the timeout
    vi.advanceTimersByTime(600);
    expect(signer.unlocked).toBe(false);
    expect(signer.key).toBeNull();

    vi.useRealTimers();
  });

  it("unlock prompts biometrics and decrypts key", async () => {
    // Register an identity first
    mockCreate(credentials);
    const { registerPasskeyIdentity } = await import("./index.js");
    const result = await registerPasskeyIdentity({ storageKey: "test_sign" });

    // Build a locked PasskeySigner
    const record = JSON.parse(localStorage.getItem("test_sign")!) as any;
    const signer = new PasskeySigner(record);

    mockGet(credentials);
    await signer.unlock();

    expect(signer.unlocked).toBe(true);
    expect(signer.key).toBeDefined();
    expect(signer.key!.length).toBe(32);

    // Verify the key matches
    expect(result.secretKey).toEqual(signer.key);

    clearPasskeyIdentity({ storageKey: "test_sign" });
  });

  it("clearKey zeroes and locks", () => {
    const key = new Uint8Array(32).fill(9);
    const record = {
      version: 2 as const,
      credentialId: "abc",
      encryptedNsec: "def",
      pubkey: "0".repeat(64),
      salt: "ghi",
      rpId: "localhost",
    };
    const signer = new PasskeySigner(record, { key });
    expect(signer.unlocked).toBe(true);

    signer.clearKey();
    expect(signer.unlocked).toBe(false);
    expect(signer.key).toBeNull();

    // Original buffer should be zeroed
    expect(Array.from(key)).toEqual(new Array(32).fill(0));
  });

  it("requires unlock before signing", async () => {
    const record = {
      version: 2 as const,
      credentialId: "abc",
      encryptedNsec: "def",
      pubkey: "0".repeat(64),
      salt: "ghi",
      rpId: "localhost",
    };
    const signer = new PasskeySigner(record);
    await expect(signer.signEvent({ kind: 1, content: "", tags: [], created_at: 0 })).rejects.toThrow("Passkey is locked");
  });
});

describe("PasskeyAccount", () => {
  let credentials: ReturnType<typeof setupCredentialsMock>;

  beforeEach(() => {
    localStorageMock.clear();
    vi.restoreAllMocks();
    credentials = setupCredentialsMock();
  });

  it("fromStoredIdentity creates locked account", async () => {
    mockCreate(credentials);
    const { registerPasskeyIdentity } = await import("./index.js");
    const result = await registerPasskeyIdentity({ storageKey: "test_acct" });

    const record = JSON.parse(localStorage.getItem("test_acct")!) as any;
    const account = PasskeyAccount.fromStoredIdentity(record);

    expect(account.pubkey).toBe(result.pubkey);
    expect(account.unlocked).toBe(false);

    clearPasskeyIdentity({ storageKey: "test_acct" });
  });

  it("fromUnlockedIdentity creates unlocked account", async () => {
    mockCreate(credentials);
    const { registerPasskeyIdentity } = await import("./index.js");
    const result = await registerPasskeyIdentity({ storageKey: "test_acct2" });

    const record = JSON.parse(localStorage.getItem("test_acct2")!) as any;
    const account = PasskeyAccount.fromUnlockedIdentity({ ...result, record });

    expect(account.pubkey).toBe(result.pubkey);
    expect(account.unlocked).toBe(true);

    clearPasskeyIdentity({ storageKey: "test_acct2" });
  });

  it("toJSON / fromJSON round-trip", async () => {
    mockCreate(credentials);
    const { registerPasskeyIdentity } = await import("./index.js");
    const result = await registerPasskeyIdentity({ storageKey: "test_json" });

    const record = JSON.parse(localStorage.getItem("test_json")!) as any;
    const account = PasskeyAccount.fromStoredIdentity(record);

    const json = account.toJSON();
    expect(json.type).toBe("passkey");
    expect(json.pubkey).toBe(result.pubkey);
    expect(json.signer.credentialId).toBe(record.credentialId);
    expect(json.signer.encryptedNsec).toBe(record.encryptedNsec);

    const restored = PasskeyAccount.fromJSON(json);
    expect(restored.pubkey).toBe(result.pubkey);
    expect(restored.unlocked).toBe(false);

    clearPasskeyIdentity({ storageKey: "test_json" });
  });

  it("unlock via account unlocks the signer", async () => {
    mockCreate(credentials);
    const { registerPasskeyIdentity } = await import("./index.js");
    await registerPasskeyIdentity({ storageKey: "test_unlock" });

    const record = JSON.parse(localStorage.getItem("test_unlock")!) as any;
    const account = PasskeyAccount.fromStoredIdentity(record);

    mockGet(credentials);
    await account.unlock();

    expect(account.unlocked).toBe(true);

    clearPasskeyIdentity({ storageKey: "test_unlock" });
  });

  it("getStoredPasskeyAccount returns null when no identity", () => {
    const account = getStoredPasskeyAccount();
    expect(account).toBeNull();
  });

  it("getStoredPasskeyAccount returns account when identity exists", async () => {
    mockCreate(credentials);
    const { registerPasskeyIdentity } = await import("./index.js");
    await registerPasskeyIdentity({ storageKey: "test_get" });

    const account = getStoredPasskeyAccount({ storageKey: "test_get" });
    expect(account).not.toBeNull();
    expect(account!.unlocked).toBe(false);

    clearPasskeyIdentity({ storageKey: "test_get" });
  });

  it("isPasskeyAccount correctly identifies PasskeyAccount", () => {
    const record = {
      version: 2 as const,
      credentialId: "abc",
      encryptedNsec: "def",
      pubkey: "0".repeat(64),
      salt: "ghi",
      rpId: "localhost",
    };
    const signer = new PasskeySigner(record);
    const account = new PasskeyAccount("0".repeat(64), signer);

    expect(isPasskeyAccount(account)).toBe(true);
    expect(isPasskeyAccount({})).toBe(false);
    expect(isPasskeyAccount(null)).toBe(false);
    expect(isPasskeyAccount(undefined)).toBe(false);
  });
});

function clearPasskeyIdentity(opts?: { storageKey?: string }) {
  const key = opts?.storageKey || "nostr_passkey_identity";
  localStorageMock.removeItem(key);
}
