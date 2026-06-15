import { BaseAccount, type SerializedAccount } from "applesauce-accounts";
import type { ISigner } from "applesauce-signers";
import { finalizeEvent } from "nostr-tools/pure";
import { encrypt as nip04Encrypt, decrypt as nip04Decrypt } from "nostr-tools/nip04";
import { encrypt as nip44Encrypt, decrypt as nip44Decrypt, getConversationKey } from "nostr-tools/nip44";
import type { NostrEvent } from "nostr-tools";
import type { EventTemplate } from "nostr-tools/pure";

import {
  type PasskeyIdentityRecord,
  type PasskeyIdentityResult,
  type PasskeyIdentityOptions,
  buildPasskeySignerShim,
  clearPasskeyIdentity,
  getStoredPasskeyPubkey,
  hasStoredPasskeyIdentity,
  readStoredPasskeyIdentity,
  unlockPasskeyIdentity,
} from "./index.js";

export class PasskeySigner implements ISigner {
  key: Uint8Array | null;
  record: PasskeyIdentityRecord;
  options?: PasskeyIdentityOptions;
  nip04: ISigner["nip04"];
  nip44: ISigner["nip44"];

  constructor(record: PasskeyIdentityRecord, key?: Uint8Array, options?: PasskeyIdentityOptions) {
    this.record = record;
    this.key = key ?? null;
    this.options = options;
    this.nip04 = {
      encrypt: (pubkey: string, plaintext: string) => this.nip04Encrypt(pubkey, plaintext),
      decrypt: (pubkey: string, ciphertext: string) => this.nip04Decrypt(pubkey, ciphertext),
    };
    this.nip44 = {
      encrypt: (pubkey: string, plaintext: string) => this.nip44Encrypt(pubkey, plaintext),
      decrypt: (pubkey: string, ciphertext: string) => this.nip44Decrypt(pubkey, ciphertext),
    };
  }

  get unlocked(): boolean {
    return this.key !== null;
  }

  clearKey(): void {
    this.key = null;
  }

  async unlock(): Promise<void> {
    if (this.key) return;
    const { secretKey } = await unlockPasskeyIdentity(this.record, this.options);
    this.key = secretKey;
  }

  private requireKey(): Uint8Array {
    if (!this.key) {
      throw new Error("Passkey is locked. Unlock it first.");
    }
    return this.key;
  }

  async getPublicKey(): Promise<string> {
    return this.record.pubkey;
  }

  async signEvent(event: EventTemplate): Promise<NostrEvent> {
    const key = this.requireKey();
    return finalizeEvent(event, key) as NostrEvent;
  }

  async nip04Encrypt(pubkey: string, plaintext: string): Promise<string> {
    const key = this.requireKey();
    return nip04Encrypt(key, pubkey, plaintext);
  }

  async nip04Decrypt(pubkey: string, ciphertext: string): Promise<string> {
    const key = this.requireKey();
    return nip04Decrypt(key, pubkey, ciphertext);
  }

  async nip44Encrypt(pubkey: string, plaintext: string): Promise<string> {
    const key = this.requireKey();
    return nip44Encrypt(plaintext, getConversationKey(key, pubkey));
  }

  async nip44Decrypt(pubkey: string, ciphertext: string): Promise<string> {
    const key = this.requireKey();
    return nip44Decrypt(ciphertext, getConversationKey(key, pubkey));
  }
}

export class PasskeyAccount<Metadata extends unknown = unknown> extends BaseAccount<
  PasskeySigner,
  PasskeyAccountSignerData,
  Metadata
> {
  static readonly type = "passkey";

  constructor(pubkey: string, signer: PasskeySigner) {
    super(pubkey, signer);
  }

  get unlocked(): boolean {
    return this.signer.unlocked;
  }

  async unlock(): Promise<void> {
    await this.signer.unlock();
  }

  toJSON(): SerializedAccount<PasskeyAccountSignerData, Metadata> {
    return super.saveCommonFields({
      signer: {
        credentialId: this.signer.record.credentialId,
        encryptedNsec: this.signer.record.encryptedNsec,
      },
    });
  }

  static fromJSON<Metadata extends unknown>(
    json: SerializedAccount<PasskeyAccountSignerData, Metadata>,
    options?: PasskeyIdentityOptions
  ): PasskeyAccount<Metadata> {
    const signer = new PasskeySigner(
      {
        version: 1,
        credentialId: json.signer.credentialId,
        encryptedNsec: json.signer.encryptedNsec,
        pubkey: json.pubkey,
      },
      undefined,
      options
    );
    const account = new PasskeyAccount<Metadata>(json.pubkey, signer);
    return super.loadCommonFields(account, json);
  }

  static fromUnlockedIdentity<Metadata extends unknown>(
    identity: PasskeyIdentityResult,
    options?: PasskeyIdentityOptions
  ): PasskeyAccount<Metadata> {
    const signer = new PasskeySigner(identity.record, identity.secretKey, options);
    return new PasskeyAccount<Metadata>(identity.pubkey, signer);
  }

  static fromStoredIdentity<Metadata extends unknown>(
    record: PasskeyIdentityRecord,
    options?: PasskeyIdentityOptions
  ): PasskeyAccount<Metadata> {
    const signer = new PasskeySigner(record, undefined, options);
    return new PasskeyAccount<Metadata>(record.pubkey, signer);
  }
}

export type PasskeyAccountSignerData = {
  credentialId: string;
  encryptedNsec: string;
};

export function isPasskeyAccount(account: unknown): account is PasskeyAccount {
  return !!account && typeof account === "object" && (account as { type?: unknown }).type === PasskeyAccount.type;
}

export function hasPasskeyIdentityOnDevice(options?: PasskeyIdentityOptions): boolean {
  return hasStoredPasskeyIdentity(options);
}

export function getPasskeyIdentityPubkey(options?: PasskeyIdentityOptions): string | null {
  return getStoredPasskeyPubkey(options);
}

export function getStoredPasskeyAccount(options?: PasskeyIdentityOptions): PasskeyAccount | null {
  const record = readStoredPasskeyIdentity(options);
  return record ? PasskeyAccount.fromStoredIdentity(record, options) : null;
}

export function buildPasskeyAccountFromIdentity(identity: PasskeyIdentityResult, options?: PasskeyIdentityOptions): PasskeyAccount {
  return PasskeyAccount.fromUnlockedIdentity(identity, options);
}

export function passkeySignerShimFromIdentity(identity: PasskeyIdentityResult) {
  return buildPasskeySignerShim(identity.secretKey);
}

export { clearPasskeyIdentity };
