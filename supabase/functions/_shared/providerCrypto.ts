// Shared AES-GCM helpers for AI provider API keys (Deno Edge Functions).
//
// The 32-byte key comes from the PROVIDER_ENCRYPTION_KEY Supabase secret
// (64 hex characters). Keys are encrypted in the edge function BEFORE they
// reach Postgres, so the database only ever stores ciphertext. The secret
// itself never leaves the function's environment.
//
// Set it with:
//   supabase secrets set PROVIDER_ENCRYPTION_KEY=$(openssl rand -hex 32)

function base64Encode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64Decode(s: string): Uint8Array<ArrayBuffer> {
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function getKey(): Promise<CryptoKey> {
  const hex = Deno.env.get('PROVIDER_ENCRYPTION_KEY') ?? '';
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(
      'PROVIDER_ENCRYPTION_KEY is not configured. Set it with: supabase secrets set PROVIDER_ENCRYPTION_KEY=$(openssl rand -hex 32)',
    );
  }
  const raw = new Uint8Array(32);
  for (let i = 0; i < 32; i++) raw[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export interface EncryptedSecret {
  ciphertext: string;
  iv: string;
}

/** Encrypt a provider API key. Returns base64 ciphertext + iv for storage. */
export async function encryptSecret(plaintext: string): Promise<EncryptedSecret> {
  const key = await getKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  return { ciphertext: base64Encode(new Uint8Array(ct)), iv: base64Encode(iv) };
}

/** Decrypt a stored provider API key. Throws when the secret is wrong or data is corrupt. */
export async function decryptSecret(ciphertext: string, iv: string): Promise<string> {
  const key = await getKey();
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64Decode(iv) },
    key,
    base64Decode(ciphertext),
  );
  return new TextDecoder().decode(pt);
}
