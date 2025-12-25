
/**
 * Project Hades Security Service
 * Implements AES-GCM encryption/decryption using Web Crypto API.
 */

const ALGORITHM = 'AES-GCM';
const IV_LENGTH = 12;

// Salt used for PBKDF2 key derivation for encryption
const ENCRYPTION_SALT = new TextEncoder().encode('hades_silicon_encryption_salt_v2');
// Salt used for identity verification hashing
const VERIFICATION_SALT = new TextEncoder().encode('hades_identity_verification_salt_v2');

async function deriveKey(password: string, salt: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 150000, // Increased iterations for higher security
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: ALGORITHM, length: 256 },
    false,
    usages
  );
}

export async function encryptData(text: string, secret: string): Promise<string> {
  try {
    const key = await deriveKey(secret, ENCRYPTION_SALT, ['encrypt']);
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const encodedText = new TextEncoder().encode(text);

    const encrypted = await window.crypto.subtle.encrypt(
      { name: ALGORITHM, iv },
      key,
      encodedText
    );

    const encryptedArray = new Uint8Array(encrypted);
    const combined = new Uint8Array(iv.length + encryptedArray.length);
    combined.set(iv);
    combined.set(encryptedArray, iv.length);

    return btoa(String.fromCharCode(...combined));
  } catch (e) {
    console.error('Encryption Failed:', e);
    return 'ENCRYPTION_ERROR';
  }
}

export async function decryptData(cipherText: string, secret: string): Promise<string> {
  try {
    const key = await deriveKey(secret, ENCRYPTION_SALT, ['decrypt']);
    const combined = new Uint8Array(
      atob(cipherText)
        .split('')
        .map((char) => char.charCodeAt(0))
    );

    const iv = combined.slice(0, IV_LENGTH);
    const data = combined.slice(IV_LENGTH);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: ALGORITHM, iv },
      key,
      data
    );

    return new TextDecoder().decode(decrypted);
  } catch (e) {
    console.error('Decryption Failed:', e);
    return 'DECRYPTION_ERROR: INVALID_KEY';
  }
}

/**
 * Hashes an ID for use as a unique storage key.
 */
export async function hashId(id: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(id.toLowerCase().trim() + 'hades_pepper_v2');
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Creates a verification hash to store in the identity registry.
 * This combines ID and password so the password is never stored raw.
 */
export async function createVerificationHash(id: string, key: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(id.toLowerCase().trim() + ":" + key);
  
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    msgUint8,
    'PBKDF2',
    false,
    ['deriveBits']
  );
  
  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: VERIFICATION_SALT,
      iterations: 50000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  const hashArray = Array.from(new Uint8Array(derivedBits));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}
