/**
 * AES-GCM encryption for credentials at rest (password / access_token / session).
 *
 * The original panel stores these in plaintext SQLite (ADR-0003: single user,
 * local machine). On Workers the database lives in Cloudflare's edge network,
 * so plaintext is not acceptable: every secret column is stored as
 * `base64(iv) + "." + base64(ciphertext)`.
 *
 * Key: `ENCRYPTION_KEY` Worker secret, base64 of 32 random bytes.
 * Generate: openssl rand -base64 32
 */

function b64encode(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function importKey(secret: string): Promise<CryptoKey> {
  const raw = b64decode(secret.trim());
  if (raw.length !== 32) throw new Error('ENCRYPTION_KEY must be base64 of 32 bytes');
  return crypto.subtle.importKey('raw', raw.buffer as ArrayBuffer, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

export async function encryptSecret(secret: string, plaintext: string): Promise<string> {
  const key = await importKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
    key,
    new TextEncoder().encode(plaintext),
  );
  return `${b64encode(iv)}.${b64encode(new Uint8Array(ct))}`;
}

export async function decryptSecret(secret: string, stored: string): Promise<string> {
  const dot = stored.indexOf('.');
  if (dot < 0) throw new Error('stored value is not an encrypted secret');
  const key = await importKey(secret);
  const iv = b64decode(stored.slice(0, dot));
  const ct = b64decode(stored.slice(dot + 1));
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
    key,
    ct.buffer as ArrayBuffer,
  );
  return new TextDecoder().decode(pt);
}

/** Encrypt only when there is a value; pass through null/undefined. */
export async function maybeEncrypt(
  secret: string,
  value: string | null | undefined,
): Promise<string | null> {
  if (value === null || value === undefined || value === '') return null;
  return encryptSecret(secret, value);
}

export async function maybeDecrypt(
  secret: string,
  stored: string | null | undefined,
): Promise<string | null> {
  if (!stored) return null;
  // Tolerate plaintext leftovers from a manual import: encrypt-on-read would
  // be nicer, but silently accepting plaintext defeats the point — fail loud.
  if (!stored.includes('.')) throw new Error('credential column holds plaintext; re-save the account');
  return decryptSecret(secret, stored);
}
