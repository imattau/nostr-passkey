import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  bytesToHex,
  hexToBytes,
  isPRFSupported,
  registerPasskeyIdentity,
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
});
