import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  bytesToHex,
  hexToBytes,
  isPRFSupported,
  registerPasskeyIdentity,
  importPasskeyIdentityFromNsec,
  unlockPasskeyIdentity,
  hasStoredPasskeyIdentity,
  getStoredPasskeyPubkey,
  clearPasskeyIdentity,
  buildPasskeySignerShim,
  isPasskeyShim,
  DEFAULT_STORAGE_KEY,
  exportPasskeyIdentityAsNsec,
} from "./index.js";

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value.toString();
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
  };
})();

Object.defineProperty(globalThis, "localStorage", {
  value: localStorageMock,
  writable: true,
});

// Mock window
Object.defineProperty(globalThis, "window", {
  value: globalThis,
  writable: true,
});

// Mock Web Crypto if needed (Node.js has crypto globally, but we might want custom setup)
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    writable: true,
  });
}

// Mock location
Object.defineProperty(globalThis, "location", {
  value: { hostname: "localhost" },
  writable: true,
});

describe("nostr-passkey core", () => {
  beforeEach(() => {
    localStorageMock.clear();
    vi.restoreAllMocks();
  });

  describe("Hex Helpers", () => {
    it("converts bytes to hex", () => {
      const bytes = new Uint8Array([0, 15, 255]);
      expect(bytesToHex(bytes)).toBe("000fff");
    });

    it("converts hex to bytes", () => {
      const hex = "000fff";
      expect(hexToBytes(hex)).toEqual(new Uint8Array([0, 15, 255]));
    });

    it("throws error on invalid hex", () => {
      expect(() => hexToBytes("not-hex")).toThrow("Invalid hex string");
    });
  });

  describe("WebAuthn Support Check", () => {
    it("returns false if navigator is not defined", async () => {
      const originalNavigator = globalThis.navigator;
      Object.defineProperty(globalThis, "navigator", {
        value: undefined,
        configurable: true,
      });

      await expect(isPRFSupported()).resolves.toBe(false);

      Object.defineProperty(globalThis, "navigator", {
        value: originalNavigator,
        configurable: true,
      });
    });
  });

  describe("Passkey registration and unlock", () => {
    beforeEach(() => {
      // Mock navigator.credentials
      const mockCredentials = {
        create: vi.fn(),
        get: vi.fn(),
      };
      Object.defineProperty(globalThis, "navigator", {
        value: { credentials: mockCredentials },
        configurable: true,
        writable: true,
      });
      // Mock PublicKeyCredential
      Object.defineProperty(globalThis, "PublicKeyCredential", {
        value: class {},
        configurable: true,
        writable: true,
      });
    });

    it("registers a new passkey identity and unlocks it", async () => {
      const prfKey = new Uint8Array(32).fill(1); // mock prf result key

      // Mock navigator.credentials.create output
      const mockCred = {
        rawId: new Uint8Array([1, 2, 3]).buffer,
        getClientExtensionResults: () => ({
          prf: {
            results: {
              first: prfKey.buffer,
            },
          },
        }),
      };

      (navigator.credentials.create as any).mockResolvedValue(mockCred);

      // Perform registration
      const result = await registerPasskeyIdentity({
        storageKey: "test_passkey",
      });

      expect(result.pubkey).toBeDefined();
      expect(result.secretKey).toBeDefined();
      expect(hasStoredPasskeyIdentity({ storageKey: "test_passkey" })).toBe(true);
      expect(getStoredPasskeyPubkey({ storageKey: "test_passkey" })).toBe(result.pubkey);

      // Mock navigator.credentials.get output for unlocking
      const mockAssertion = {
        getClientExtensionResults: () => ({
          prf: {
            results: {
              first: prfKey.buffer,
            },
          },
        }),
      };
      (navigator.credentials.get as any).mockResolvedValue(mockAssertion);

      // Perform unlock
      const unlocked = await unlockPasskeyIdentity(undefined, { storageKey: "test_passkey" });
      expect(unlocked.pubkey).toBe(result.pubkey);
      expect(unlocked.secretKey).toEqual(result.secretKey);

      // Export as nsec
      const exportedNsec = await exportPasskeyIdentityAsNsec(undefined, { storageKey: "test_passkey" });
      expect(exportedNsec).toBeTypeOf("string");
      expect(exportedNsec.startsWith("nsec1")).toBe(true);

      // Verify signers
      const shim = buildPasskeySignerShim(unlocked.secretKey);
      expect(isPasskeyShim(shim)).toBe(true);
      expect(await shim.getPublicKey()).toBe(unlocked.pubkey);

      // Cleanup
      clearPasskeyIdentity({ storageKey: "test_passkey" });
      expect(hasStoredPasskeyIdentity({ storageKey: "test_passkey" })).toBe(false);
    });
  });

  describe("Security", () => {
    beforeEach(() => {
      const mockCredentials = {
        create: vi.fn(),
        get: vi.fn(),
      };
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
    });

    it("rejects nsec input that exceeds maximum length", async () => {
      const longInput = "0".repeat(257);
      await expect(importPasskeyIdentityFromNsec(longInput)).rejects.toThrow("Input exceeds maximum length.");
    });

    it("rejects hex input that exceeds maximum length", async () => {
      const longHex = "a".repeat(257);
      await expect(importPasskeyIdentityFromNsec(longHex)).rejects.toThrow("Input exceeds maximum length.");
    });

    it("destroyed shim rejects all operations", async () => {
      const key = new Uint8Array(32).fill(42);
      const shim = buildPasskeySignerShim(key);

      shim.destroy();

      await expect(shim.getPublicKey()).rejects.toThrow("Signer has been destroyed.");
      await expect(shim.signEvent({ kind: 1, content: "", tags: [], created_at: 0 })).rejects.toThrow("Signer has been destroyed.");
      await expect(shim.nip04.encrypt("a".repeat(64), "hello")).rejects.toThrow("Signer has been destroyed.");
      await expect(shim.nip04.decrypt("a".repeat(64), "hello")).rejects.toThrow("Signer has been destroyed.");
      await expect(shim.nip44.encrypt("a".repeat(64), "hello")).rejects.toThrow("Signer has been destroyed.");
      await expect(shim.nip44.decrypt("a".repeat(64), "hello")).rejects.toThrow("Signer has been destroyed.");
    });

    it("destroy zeroes the underlying key buffer", () => {
      const key = new Uint8Array([1, 2, 3, 4]);
      const shim = buildPasskeySignerShim(key);
      shim.destroy();
      // The original buffer should be zeroed
      expect(Array.from(key)).toEqual([0, 0, 0, 0]);
    });

    it("tampered stored pubkey fails unlock verification", async () => {
      const prfKey = new Uint8Array(32).fill(1);

      // Register
      const mockCred = {
        rawId: new Uint8Array([1, 2, 3]).buffer,
        getClientExtensionResults: () => ({
          prf: { results: { first: prfKey.buffer } },
        }),
      };
      (navigator.credentials.create as any).mockResolvedValue(mockCred);

      const result = await registerPasskeyIdentity({ storageKey: "test_tamper" });

      // Tamper with stored pubkey
      const stored = JSON.parse(localStorage.getItem("test_tamper")!);
      stored.pubkey = "a".repeat(64);
      localStorage.setItem("test_tamper", JSON.stringify(stored));

      // Mock unlock - same PRF result but pubkey won't match decrypted key
      const mockAssertion = {
        getClientExtensionResults: () => ({
          prf: { results: { first: prfKey.buffer } },
        }),
      };
      (navigator.credentials.get as any).mockResolvedValue(mockAssertion);

      await expect(unlockPasskeyIdentity(undefined, { storageKey: "test_tamper" })).rejects.toThrow("Passkey identity mismatch.");

      clearPasskeyIdentity({ storageKey: "test_tamper" });
    });

    it("stored record is v2 format with all security fields", async () => {
      const prfKey = new Uint8Array(32).fill(1);
      const mockCred = {
        rawId: new Uint8Array([4, 5, 6]).buffer,
        getClientExtensionResults: () => ({
          prf: { results: { first: prfKey.buffer } },
        }),
      };
      (navigator.credentials.create as any).mockResolvedValue(mockCred);

      await registerPasskeyIdentity({ storageKey: "test_format" });

      const stored = JSON.parse(localStorage.getItem("test_format")!);
      expect(stored.version).toBe(2);
      expect(typeof stored.salt).toBe("string");
      expect(stored.salt.length).toBeGreaterThan(0);
      expect(typeof stored.rpId).toBe("string");
      expect(stored.rpId.length).toBeGreaterThan(0);
      expect(typeof stored.credentialId).toBe("string");
      expect(typeof stored.encryptedNsec).toBe("string");
      expect(typeof stored.pubkey).toBe("string");
      expect(stored.pubkey).toMatch(/^[0-9a-fA-F]{64}$/);

      clearPasskeyIdentity({ storageKey: "test_format" });
    });

    it("uses custom storage backend", async () => {
      const prfKey = new Uint8Array(32).fill(1);
      const mockCred = {
        rawId: new Uint8Array([7, 8, 9]).buffer,
        getClientExtensionResults: () => ({
          prf: { results: { first: prfKey.buffer } },
        }),
      };
      (navigator.credentials.create as any).mockResolvedValue(mockCred);

      const customStore: Record<string, string> = {};
      const storage = {
        getItem: (key: string) => customStore[key] ?? null,
        setItem: (key: string, value: string) => { customStore[key] = value; },
        removeItem: (key: string) => { delete customStore[key]; },
      };

      const result = await registerPasskeyIdentity({ storageKey: "custom_key", storage });

      // Should NOT be in localStorage
      expect(localStorage.getItem("custom_key")).toBeNull();
      // Should be in custom store
      expect(customStore["custom_key"]).toBeDefined();

      const parsed = JSON.parse(customStore["custom_key"]!);
      expect(parsed.version).toBe(2);
      expect(parsed.pubkey).toBe(result.pubkey);

      // Unlock with custom storage
      const mockAssertion = {
        getClientExtensionResults: () => ({
          prf: { results: { first: prfKey.buffer } },
        }),
      };
      (navigator.credentials.get as any).mockResolvedValue(mockAssertion);

      const unlocked = await unlockPasskeyIdentity(undefined, { storageKey: "custom_key", storage });
      expect(unlocked.pubkey).toBe(result.pubkey);

      // Clear with custom storage
      clearPasskeyIdentity({ storageKey: "custom_key", storage });
      expect(customStore["custom_key"]).toBeUndefined();
    });

    it("migrates v1 record to v2 on unlock", async () => {
      const prfKey = new Uint8Array(32).fill(99);
      const secretKey = new Uint8Array(32).fill(88);
      const { getPublicKey } = await import("nostr-tools/pure");
      const pubkey = getPublicKey(secretKey);
      const nsecHex = Array.from(secretKey, (b) => b.toString(16).padStart(2, "0")).join("");

      // Create a proper v1 NIP-44 encrypted nsec using the PRF key
      const { encrypt: nip44Encrypt } = await import("nostr-tools/nip44");
      const encryptedNsec = nip44Encrypt(nsecHex, prfKey);

      const v1Record = {
        version: 1,
        credentialId: "dGVzdC12MS1jcmVk",
        encryptedNsec,
        pubkey,
      };

      localStorage.setItem("test_migration", JSON.stringify(v1Record));

      // Mock get with the same PRF key plus a new v2 key
      const mockAssertion = {
        getClientExtensionResults: () => ({
          prf: { results: { first: prfKey.buffer, second: prfKey.buffer } },
        }),
      };
      (navigator.credentials.get as any).mockResolvedValue(mockAssertion);

      const unlocked = await unlockPasskeyIdentity(undefined, { storageKey: "test_migration" });

      // Check stored record is now v2
      const afterMigration = JSON.parse(localStorage.getItem("test_migration")!);
      expect(afterMigration.version).toBe(2);
      expect(typeof afterMigration.salt).toBe("string");
      expect(afterMigration.salt.length).toBeGreaterThan(0);
      expect(typeof afterMigration.rpId).toBe("string");
      expect(afterMigration.pubkey).toBe(pubkey);
      expect(unlocked.pubkey).toBe(pubkey);

      clearPasskeyIdentity({ storageKey: "test_migration" });
    });
  });
});
