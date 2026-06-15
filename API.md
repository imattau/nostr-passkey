# API Reference: `nostr-passkey`

This document details the public API surface exported by the `nostr-passkey` package.

---

## 1. Core Module (`nostr-passkey`)

The core module contains standard functions for checking browser support, enrolling credentials, and managing encrypted key records.

### Functions

#### `isPRFSupported()`
Checks whether the current browser environment supports the WebAuthn PRF (Pseudo-Random Function) extension.
- **Returns**: `Promise<boolean>`

```typescript
import { isPRFSupported } from 'nostr-passkey';
const supported = await isPRFSupported();
```

#### `registerPasskeyIdentity(options?)`
Enrolls a new passkey credential on the device and generates a brand new Nostr private key.
- **Parameters**:
  - `options?: PasskeyIdentityOptions` (see [Types](#types) below)
- **Returns**: `Promise<PasskeyIdentityResult>`

#### `importPasskeyIdentityFromNsec(nsec, options?)`
Enrolls a passkey credential and encrypts an existing Nostr private key (as a hex string or `nsec` string format).
- **Parameters**:
  - `nsec: string` - The existing secret key.
  - `options?: PasskeyIdentityOptions`
- **Returns**: `Promise<PasskeyIdentityResult>`

#### `unlockPasskeyIdentity(record?, options?)`
Prompts the browser to verify the passkey (via FaceID/TouchID/PIN) and decrypts the stored Nostr key.
- **Parameters**:
  - `record?: PasskeyIdentityRecord` - Optional custom record to decrypt. If omitted, the function reads from `localStorage`.
  - `options?: PasskeyIdentityOptions`
- **Returns**: `Promise<PasskeyIdentityResult>`

#### `buildPasskeySignerShim(secretKey)`
Returns a standard NIP-07-compliant signer shim wrapper that holds the decrypted key in-memory.
- **Parameters**:
  - `secretKey: Uint8Array` - The decrypted private key.
- **Returns**: `PasskeySignerShim`

#### `isPasskeyShim(value)`
Helper check to verify if a given signer (like `window.nostr`) was built by `nostr-passkey`.
- **Returns**: `boolean`

#### `clearPasskeyIdentity(options?)`
Clears the encrypted passkey identity record from `localStorage`.
- **Parameters**:
  - `options?: PasskeyIdentityOptions`

---

## 2. Applesauce Module (`nostr-passkey/applesauce`)

Adapter bindings for applications leveraging the `applesauce-accounts` framework.

### Classes

#### `PasskeySigner`
Implements the `ISigner` interface from `applesauce-signers`. Holds the decrypted key securely in-memory.
- **Constructor**: `new PasskeySigner(record, key?, options?)`
- **Properties**:
  - `unlocked: boolean` - Returns `true` if the key is decrypted in memory.
- **Methods**:
  - `unlock(): Promise<void>` - Triggers biometrics check and decrypts the key.
  - `clearKey(): void` - Immediately zeroes out the in-memory private key.
  - `signEvent(event): Promise<NostrEvent>` - Signs a Nostr event.
  - `nip04Encrypt(pubkey, plaintext) / nip04Decrypt(...)`
  - `nip44Encrypt(pubkey, plaintext) / nip44Decrypt(...)`

#### `PasskeyAccount`
Extends `BaseAccount` from `applesauce-accounts`.
- **Static Property**: `type = "passkey"`
- **Static Methods**:
  - `fromStoredIdentity(record, options?)` - Restores a locked account wrapper.
  - `fromUnlockedIdentity(identity, options?)` - Creates an unlocked account wrapper.

### Functions

#### `getStoredPasskeyAccount(options?)`
Reads the stored credential and returns a `PasskeyAccount` instance (locked by default).
- **Returns**: `PasskeyAccount | null`

#### `hasPasskeyIdentityOnDevice(options?)`
- **Returns**: `boolean`

---

## 3. Types

### `PasskeyIdentityRecord`
```typescript
interface PasskeyIdentityRecord {
  version: 1;
  credentialId: string;   // Base64Url raw identifier
  encryptedNsec: string;  // NIP-44 encrypted private key hex
  pubkey: string;         // Plaintext public key hex
}
```

### `PasskeyIdentityOptions`
Customize settings to match your application:
```typescript
interface PasskeyIdentityOptions {
  rpName?: string;         // Relaying Party Name (e.g. "My Nostr App")
  rpId?: string;           // Relaying Party Domain (defaults to location.hostname)
  userName?: string;       // WebAuthn credential name user identifier
  displayName?: string;    // WebAuthn display name
  storageKey?: string;     // Custom localStorage key
  prfSalt?: Uint8Array;    // Custom 32-byte salt for PRF derivation
  prfSaltString?: string;  // Custom salt string (default: "nostr-passkey-nsec-v1")
}
```
