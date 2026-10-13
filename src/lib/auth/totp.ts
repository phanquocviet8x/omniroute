/**
 * TOTP (RFC 6238) / HOTP (RFC 4226) second factor for the dashboard login.
 *
 * Implemented with `node:crypto` only — no new runtime dependency, so a deploy
 * never has to touch the production `node_modules`. The test vectors in
 * `tests/unit/twofa-totp.test.ts` are the official RFC vectors, which is what
 * makes this interoperable with Google Authenticator / Authy / 1Password.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const DEFAULT_DIGITS = 6;
const DEFAULT_PERIOD_SECONDS = 30;
const RECOVERY_SECRET_BYTES = 10; // 10 bytes → 50 bits per code after base32 split

/** RFC 4648 base32, unpadded (otpauth:// URIs reject `=`). */
export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/** Strict RFC 4648 base32 decode — throws on any character outside the alphabet. */
export function base32Decode(input: string): Buffer {
  const normalized = input.replace(/=+$/, "").toUpperCase();
  if (normalized.length === 0) {
    throw new Error("Empty base32 input");
  }
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid base32 character: ${char}`);
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** RFC 4226 HOTP. */
export function hotp(secret: Buffer, counter: number, digits: number = DEFAULT_DIGITS): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(Math.max(0, Math.trunc(counter))));
  const digest = createHmac("sha1", secret).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, "0");
}

export interface TotpOptions {
  /** Unix seconds; defaults to now. Used by the RFC test vectors. */
  atSeconds?: number;
  digits?: number;
  periodSeconds?: number;
}

/** RFC 6238 TOTP. */
export function totp(secret: Buffer, options: TotpOptions = {}): string {
  const period = options.periodSeconds ?? DEFAULT_PERIOD_SECONDS;
  const at = options.atSeconds ?? Math.floor(Date.now() / 1000);
  const counter = Math.floor(at / period);
  return hotp(secret, counter, options.digits ?? DEFAULT_DIGITS);
}

export interface TotpVerifyOptions extends TotpOptions {
  /** Verification clock; defaults to now. */
  nowSeconds?: number;
  /** Allowed clock-skew window in steps either side of now. Default 1 (±30s). */
  window?: number;
}

/**
 * Constant-time verification of a submitted code against the current window.
 * A wrong length / non-numeric code is rejected before any HMAC work.
 */
export function verifyTotp(secret: Buffer, code: string, options: TotpVerifyOptions = {}): boolean {
  const digits = options.digits ?? DEFAULT_DIGITS;
  if (typeof code !== "string" || code.length !== digits || !/^\d+$/.test(code)) {
    return false;
  }
  if (secret.length === 0) return false;

  const period = options.periodSeconds ?? DEFAULT_PERIOD_SECONDS;
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const window = Math.max(0, options.window ?? 1);
  const currentCounter = Math.floor(now / period);

  const submitted = Buffer.from(code, "ascii");
  for (let step = -window; step <= window; step++) {
    const counter = currentCounter + step;
    if (counter < 0) continue;
    const expected = Buffer.from(hotp(secret, counter, digits), "ascii");
    if (expected.length === submitted.length && timingSafeEqual(expected, submitted)) {
      return true;
    }
  }
  return false;
}

/** Fresh 160-bit base32 secret (20 bytes → 32 chars) for authenticator apps. */
export function generateSecret(bytes: number = 20): string {
  return base32Encode(randomBytes(bytes));
}

/** `otpauth://totp/` URI, issuer-qualified and URL-encoded. */
export function buildOtpauthUri(secretBase32: string, account: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: "SHA1",
    digits: String(DEFAULT_DIGITS),
    period: String(DEFAULT_PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/** Human-typed one-time recovery codes: `ABCDE-FGHJK` (50 bits each). */
export function generateRecoveryCodes(count: number = 10): string[] {
  const codes: string[] = [];
  while (codes.length < count) {
    const raw = base32Encode(randomBytes(RECOVERY_SECRET_BYTES)); // 16 chars
    const code = `${raw.slice(0, 5)}-${raw.slice(5, 10)}`;
    if (!codes.includes(code)) codes.push(code);
  }
  return codes;
}

/** Normalise user input so `abcde-fghjk` and `ABCDEFGHIJK` hash identically. */
function normalizeRecoveryCode(code: string): string {
  return String(code ?? "")
    .toUpperCase()
    .replace(/[\s-]+/g, "");
}

/**
 * Recovery codes are 50-bit random values, so a plain SHA-256 digest is
 * sufficient (no low-entropy guessing surface like a user password).
 */
export function hashRecoveryCode(code: string): string {
  return createHash("sha256").update(normalizeRecoveryCode(code), "utf8").digest("hex");
}

/**
 * Consume a recovery code from a hash → code map. Returns true on first use,
 * false when the code was never present or was already redeemed.
 */
export function consumeRecoveryCode(store: Map<string, string>, code: string): boolean {
  const key = hashRecoveryCode(code);
  if (!store.has(key)) return false;
  store.delete(key);
  return true;
}
