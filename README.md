# nostr-passkey

Nostr authentication and key management using WebAuthn Passkeys PRF (Pseudo-Random Function) extension.

Securely encrypt your Nostr private keys (`nsec`) locally on the client using hardware-backed cryptographic keys (FaceID, TouchID, Windows Hello, YubiKeys) and decrypt them purely in-memory.

## Install

Install `nostr-passkey` along with its peer dependency `nostr-tools`:

```bash
npm install nostr-passkey nostr-tools
```

*Note: If you are using the Applesauce account adapter, ensure you have `applesauce-accounts` and `applesauce-signers` installed.*

---

## Core Features
- **Zero-Password Login**: Derives symmetric encryption keys directly from your authenticator chip using the WebAuthn PRF extension.
- **In-Memory Signers**: Decrypts the private key on-demand into memory; the decrypted key is never written to disk, can be proactively zeroed via `destroy()`, and is wiped on page refresh.
- **NIP-07 Shim**: Exports a standard NIP-07 (`window.nostr`) shim to easily drop into existing applications.
- **Applesauce Integration**: Native adapters for `applesauce-accounts` (`PasskeyAccount` and `PasskeySigner`).

---

## Browser Requirements
This library requires browser support for **WebAuthn PRF (Pseudo-Random Function)**. You can check for capability at runtime:

```typescript
import { isPRFSupported } from 'nostr-passkey';

if (await isPRFSupported()) {
  console.log("Hardware-backed encryption is supported!");
}
```

---

## Quick Start (Core API)

### 1. Register a new Passkey and generate a Nostr Key
```typescript
import { registerPasskeyIdentity } from 'nostr-passkey';

// Prompts WebAuthn registration and generates a new random Nostr key pair
const { secretKey, pubkey, record } = await registerPasskeyIdentity({
  rpName: "My Nostr App"
});
```

### 2. Import an existing `nsec` into a Passkey
```typescript
import { importPasskeyIdentityFromNsec } from 'nostr-passkey';

const { secretKey, pubkey } = await importPasskeyIdentityFromNsec("nsec1...", {
  rpName: "My Nostr App"
});
```

### 3. Unlock a stored identity
```typescript
import { unlockPasskeyIdentity, buildPasskeySignerShim } from 'nostr-passkey';

// Prompts user for biometrics/PIN and decrypts nsec
const { secretKey, pubkey } = await unlockPasskeyIdentity();

// Build a standard window.nostr shim
const nostrSigner = buildPasskeySignerShim(secretKey);
window.nostr = nostrSigner;

// When done, zero the key from memory
nostrSigner.destroy();
```

---

## Applesauce Accounts Integration

If you use the `applesauce` state and accounts framework:

```typescript
import { PasskeyAccount, getStoredPasskeyAccount } from 'nostr-passkey/applesauce';

// 1. Retrieve the stored account from device identity
const account = getStoredPasskeyAccount();

if (account) {
  // 2. Prompt user biometrics to unlock the signer
  await account.unlock();
  
  // 3. Ready to sign events!
  const event = await account.signer.signEvent({
    kind: 1,
    content: "Hello from a Passkey-secured account!",
    tags: [],
    created_at: Math.floor(Date.now() / 1000)
  });
}
```

---

## License
MIT
