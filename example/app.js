import {
  isPRFSupported,
  registerPasskeyIdentity,
  importPasskeyIdentityFromNsec,
  unlockPasskeyIdentity,
  hasStoredPasskeyIdentity,
  getStoredPasskeyPubkey,
  readStoredPasskeyIdentity,
  clearPasskeyIdentity,
  buildPasskeySignerShim
} from '../dist/index.js';

let activeSigner = null;

// DOM Elements
const prfSupportBadge = document.getElementById('prf-support-badge');
const identityStatusBadge = document.getElementById('identity-status-badge');
const identityDetails = document.getElementById('identity-details');
const storedPubkeyDisplay = document.getElementById('stored-pubkey-display');
const storedCredDisplay = document.getElementById('stored-cred-display');

const importNsecInput = document.getElementById('import-nsec-input');
const btnRegister = document.getElementById('btn-register');
const btnClear = document.getElementById('btn-clear');

const signCard = document.getElementById('sign-card');
const btnUnlock = document.getElementById('btn-unlock');
const btnSign = document.getElementById('btn-sign');
const signOutput = document.getElementById('sign-output');

// Check capabilities & status on load
async function init() {
  const prfOk = await isPRFSupported();
  if (prfOk) {
    prfSupportBadge.textContent = 'Supported';
    prfSupportBadge.className = 'status-badge unlocked';
  } else {
    prfSupportBadge.textContent = 'Not Supported';
    prfSupportBadge.className = 'status-badge locked';
  }

  updateIdentityStatus();
}

function updateIdentityStatus() {
  const hasIdentity = hasStoredPasskeyIdentity();
  
  if (hasIdentity) {
    const record = readStoredPasskeyIdentity();
    identityStatusBadge.textContent = 'Locked';
    identityStatusBadge.className = 'status-badge locked';
    
    // Show details
    identityDetails.style.display = 'block';
    storedPubkeyDisplay.value = record.pubkey;
    storedCredDisplay.value = record.credentialId;

    // Show utility cards
    btnClear.style.display = 'inline-block';
    signCard.style.display = 'block';
    btnUnlock.style.display = 'inline-block';
    btnSign.style.display = 'none'; // Lock status hide signing button
  } else {
    identityStatusBadge.textContent = 'No Identity';
    identityStatusBadge.className = 'status-badge not-registered';
    
    identityDetails.style.display = 'none';
    btnClear.style.display = 'none';
    signCard.style.display = 'none';
  }
}

// Enroll / Setup click handler
btnRegister.addEventListener('click', async () => {
  const nsec = importNsecInput.value.trim();
  
  try {
    let result;
    if (nsec) {
      result = await importPasskeyIdentityFromNsec(nsec, { rpName: "Nostr Passkey Demo" });
      alert("Successfully imported identity!");
    } else {
      result = await registerPasskeyIdentity({ rpName: "Nostr Passkey Demo" });
      alert("Successfully registered new Passkey identity!");
    }
    
    importNsecInput.value = '';
    updateIdentityStatus();
  } catch (err) {
    console.error("Registration failed:", err);
    alert("An error occurred during registration. Check the console for details.");
  }
});

// Unlock click handler
btnUnlock.addEventListener('click', async () => {
  try {
    const { secretKey, pubkey } = await unlockPasskeyIdentity();
    activeSigner = buildPasskeySignerShim(secretKey);
    
    identityStatusBadge.textContent = 'Unlocked';
    identityStatusBadge.className = 'status-badge unlocked';
    
    btnUnlock.style.display = 'none';
    btnSign.style.display = 'inline-block';
    
    alert("Passkey unlocked. Decrypted key loaded in-memory!");
  } catch (err) {
    console.error("Unlock failed:", err);
    alert("An error occurred during unlock. Check the console for details.");
  }
});

// Sign Test Event click handler
btnSign.addEventListener('click', async () => {
  if (!activeSigner) {
    alert("Please unlock the passkey first!");
    return;
  }
  
  try {
    const template = {
      kind: 1,
      content: "Hello Nostr! This event was signed using WebAuthn Passkeys and the nostr-passkey library.",
      tags: [],
      created_at: Math.floor(Date.now() / 1000)
    };
    
    const signedEvent = await activeSigner.signEvent(template);
    signOutput.textContent = JSON.stringify(signedEvent, null, 2);
  } catch (err) {
    console.error("Signing failed:", err);
    alert("An error occurred during signing. Check the console for details.");
  }
});

// Clear / Delete click handler
btnClear.addEventListener('click', () => {
  if (confirm("Are you sure you want to delete this identity from this browser?")) {
    clearPasskeyIdentity();
    activeSigner = null;
    updateIdentityStatus();
  }
});

// Run init
init();
