import test from "node:test";
import assert from "node:assert/strict";

/**
 * RED contract for the TOTP second factor (RFC 4226 HOTP + RFC 6238 TOTP),
 * implemented in `src/lib/auth/totp.ts` with node:crypto only (no new deps).
 *
 * Vectors are the official test vectors from the RFCs — they are what prove
 * the implementation interoperates with Google Authenticator / Authy / 1Password.
 */
const totp = await import("../../src/lib/auth/totp.ts");

const RFC4226_SECRET = "12345678901234567890"; // ASCII, RFC 4226 §5.3
const RFC4226_CODES = [
  "755224",
  "287082",
  "359152",
  "969429",
  "338314",
  "254676",
  "287922",
  "162583",
  "399871",
  "520489",
];

// RFC 6238 §A.1 — SHA-1 vectors, 8-digit codes, same ASCII secret.
const RFC6238_SHA1: Array<[number, string]> = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
  [20000000000, "65353130"],
];

test("base32 encodes RFC 4226 secret without padding and decodes back", () => {
  const encoded = totp.base32Encode(Buffer.from(RFC4226_SECRET, "ascii"));
  // RFC 4648 alphabet, no '=' padding — required by otpauth:// URIs.
  assert.match(encoded, /^[A-Z2-7]+$/);
  assert.equal(Buffer.from(encoded, "ascii").toString("ascii").includes("="), false);
  assert.equal(totp.base32Decode(encoded).toString("ascii"), RFC4226_SECRET);
});

test("base32 decode rejects non-alphabet input", () => {
  assert.throws(() => totp.base32Decode("0189")); // 0,1,8,9 are not RFC 4648 chars
});

test("hotp matches all ten RFC 4226 test vectors", () => {
  const secret = Buffer.from(RFC4226_SECRET, "ascii");
  for (let counter = 0; counter < RFC4226_CODES.length; counter++) {
    assert.equal(totp.hotp(secret, counter, 6), RFC4226_CODES[counter], `counter ${counter}`);
  }
});

test("totp matches the RFC 6238 SHA-1 time-based vectors", () => {
  const secret = Buffer.from(RFC4226_SECRET, "ascii");
  for (const [t, expected] of RFC6238_SHA1) {
    assert.equal(totp.totp(secret, { atSeconds: t, digits: 8 }), expected, `T=${t}`);
  }
});

test("generateSecret returns a 160-bit base32 secret (20 bytes → 32 chars)", () => {
  const secret = totp.generateSecret();
  assert.match(secret, /^[A-Z2-7]{32}$/);
  assert.notEqual(totp.generateSecret(), secret, "secrets must be unique per call");
  // Round-trips through the decoder, i.e. it is a usable TOTP secret.
  assert.equal(totp.base32Decode(secret).length, 20);
});

test("buildOtpauthUri produces an issuer-qualified otpauth:// URI", () => {
  const uri = totp.buildOtpauthUri(totp.generateSecret(), "admin@omniroute", "OmniRoute");
  assert.ok(uri.startsWith("otpauth://totp/"), uri);
  assert.ok(uri.includes("issuer=OmniRoute"), uri);
  assert.ok(uri.includes("secret="), uri);
  // Issuer must be URL-encoded, never raw-spaced.
  assert.equal(uri.includes(" "), false);
});

test("verifyTotp accepts codes in the ±1 step window and rejects outside it", () => {
  const secret = Buffer.from(RFC4226_SECRET, "ascii");
  const now = 1_700_000_000; // fixed clock → deterministic
  const period = 30;
  const current = totp.totp(secret, { atSeconds: now });
  const previous = totp.totp(secret, { atSeconds: now - period });
  const next = totp.totp(secret, { atSeconds: now + period });
  const far = totp.totp(secret, { atSeconds: now + period * 3 });

  assert.equal(totp.verifyTotp(secret, current, { nowSeconds: now }), true);
  assert.equal(totp.verifyTotp(secret, previous, { nowSeconds: now }), true);
  assert.equal(totp.verifyTotp(secret, next, { nowSeconds: now }), true);
  assert.equal(totp.verifyTotp(secret, far, { nowSeconds: now }), false);
});

test("verifyTotp rejects malformed and wrong-length codes", () => {
  const secret = Buffer.from(RFC4226_SECRET, "ascii");
  const now = 1_700_000_000;
  assert.equal(totp.verifyTotp(secret, "", { nowSeconds: now }), false);
  assert.equal(totp.verifyTotp(secret, "12345", { nowSeconds: now }), false);
  assert.equal(totp.verifyTotp(secret, "abcdef", { nowSeconds: now }), false);
  assert.equal(totp.verifyTotp(secret, "000000", { nowSeconds: now }), false);
});

test("recovery codes: unique, canonical format, one-time consumption", () => {
  const codes = totp.generateRecoveryCodes(10);
  assert.equal(codes.length, 10);
  assert.equal(new Set(codes).size, 10, "recovery codes must be unique");
  for (const code of codes) {
    assert.match(code, /^[A-Z2-7]{5}-[A-Z2-7]{5}$/, code);
  }

  const store = new Map<string, string>(codes.map((c) => [totp.hashRecoveryCode(c), c]));
  const first = codes[0];
  assert.equal(totp.consumeRecoveryCode(store, first), true, "first use must succeed");
  assert.equal(totp.consumeRecoveryCode(store, first), false, "second use must fail");
  assert.equal(totp.consumeRecoveryCode(store, codes[1]), true, "other codes stay valid");
});
