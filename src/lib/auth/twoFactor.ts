/**
 * Dashboard second factor (TOTP) state + pending-login token.
 *
 * Storage lives in the existing `key_value` settings namespace (same pattern as
 * `oidcClientSecret`): the secret is written through `encrypt()` so it is at
 * rest protected whenever `STORAGE_ENCRYPTION_KEY` is configured, recovery
 * codes are stored as SHA-256 hashes only, and the enabled flag is a plain bool.
 *
 * Security invariants:
 *  - The pending token handed out after a correct password is signed with a key
 *    DERIVED from JWT_SECRET, so it can never verify as an `auth_token`
 *    (`isDashboardSessionAuthenticated` only checks the signature + expiry).
 *  - `enabled` is authoritative: if the secret becomes undecryptable after a
 *    key rotation, TOTP cannot verify but recovery codes still work — 2FA fails
 *    closed instead of silently switching itself off.
 */
import { createHmac, createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { getSettings, updateSettings } from "@/lib/db/settings";
import { decrypt } from "@/lib/db/encryption";
import {
  ensurePersistentManagementPasswordHash,
  getStoredManagementPassword,
  verifyManagementPassword,
} from "@/lib/auth/managementPassword";
import {
  base32Decode,
  buildOtpauthUri,
  consumeRecoveryCode,
  generateRecoveryCodes,
  generateSecret,
  hashRecoveryCode,
  verifyTotp,
} from "@/lib/auth/totp";

const ENABLED_KEY = "twoFactorEnabled";
const SECRET_KEY = "twoFactorSecret";
const RECOVERY_KEY = "twoFactorRecoveryCodes";

/**
 * Setting keys that must never leave the server (stripped from GET
 * /api/settings, JSON export and JSON import). Exported so those routes and
 * their tests share one list.
 */
export const TWO_FACTOR_PRIVATE_SETTING_KEYS = [SECRET_KEY, RECOVERY_KEY] as const;

const PENDING_TOKEN_CONTEXT = "omniroute-2fa-pending-v1";
const PENDING_TOKEN_TTL_SECONDS = 5 * 60;
const ISSUER = "OmniRoute";
const RECOVERY_CODE_COUNT = 10;

export interface TwoFactorState {
  /** Authoritative flag — 2FA is enforced when this is true. */
  enabled: boolean;
  /** A TOTP secret has been provisioned (may be pending first confirmation). */
  provisioned: boolean;
  /** Decrypted TOTP secret, or "" when absent/undecryptable. */
  secret: string;
  /** SHA-256 hashes of the outstanding recovery codes. */
  recoveryCodes: string[];
}

export type TwoFactorResult<T = object> =
  ({ ok: true } & T) | { ok: false; status: number; error: string };

function readString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

// ──── TOTP secret at-rest encryption ─────────────────────────────────────────
//
// `encrypt()` is passthrough when STORAGE_ENCRYPTION_KEY is unset, which would
// store the TOTP secret as plaintext. The second factor must stay secret even
// on deployments without a storage key, so the secret gets its own AES-256-GCM
// layer keyed by HMAC(JWT_SECRET, context) — the same trust root as the
// pending-login token, never persisted or logged.

const SECRET_ENC_CONTEXT = "omniroute-2fa-secret-enc-v1";

function getSecretEncryptionKey(): Buffer | null {
  const secret = process.env.JWT_SECRET?.trim();
  if (!secret) return null;
  return createHmac("sha256", secret).update(SECRET_ENC_CONTEXT).digest();
}

function encryptTotpSecret(plaintext: string): string {
  const key = getSecretEncryptionKey();
  if (!key) {
    throw new Error("JWT_SECRET is not set — cannot safely store the 2FA secret");
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `totpenc:v1:${iv.toString("hex")}:${ciphertext.toString("hex")}:${authTag.toString("hex")}`;
}

function decryptTotpSecret(stored: string): string {
  const key = getSecretEncryptionKey();
  if (!key || !stored.startsWith("totpenc:v1:")) {
    // Not produced by this envelope (empty or legacy passthrough value) —
    // fall back to the storage-layer decrypt for compatibility.
    return (stored && decrypt(stored)) || "";
  }
  const parts = stored.split(":");
  if (parts.length !== 5) return "";
  try {
    const iv = Buffer.from(parts[2], "hex");
    const ciphertext = Buffer.from(parts[3], "hex");
    const authTag = Buffer.from(parts[4], "hex");
    const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    return "";
  }
}

export async function getTwoFactorState(): Promise<TwoFactorState> {
  const settings = (await getSettings()) as Record<string, unknown>;
  const storedSecret = readString(settings[SECRET_KEY]);
  const secret = (storedSecret && decryptTotpSecret(storedSecret)) || "";
  const rawCodes = Array.isArray(settings[RECOVERY_KEY]) ? settings[RECOVERY_KEY] : [];
  const recoveryCodes = rawCodes.filter((code): code is string => typeof code === "string");
  return {
    enabled: settings[ENABLED_KEY] === true,
    provisioned: storedSecret.length > 0,
    secret,
    recoveryCodes,
  };
}

/** Re-authentication gate for enrollment/disable: the management password. */
export async function verifyTwoFactorPassword(password: unknown): Promise<boolean> {
  return verifyPasswordReauth(password);
}

async function verifyPasswordReauth(password: unknown): Promise<boolean> {
  if (typeof password !== "string" || !password) return false;
  const settings = (await getSettings()) as Record<string, unknown>;
  const ensured = await ensurePersistentManagementPasswordHash({
    settings,
    source: "auth.2fa",
  });
  const hash = getStoredManagementPassword(ensured.settings);
  if (!hash) return false;
  return verifyManagementPassword(password, hash);
}

/**
 * Generate (or rotate) a TOTP secret. Does NOT enable 2FA — the operator must
 * confirm a first valid code via `enableTwoFactor`.
 */
export async function provisionTwoFactorSecret(
  account: string = "dashboard"
): Promise<TwoFactorResult<{ secret: string; otpauthUri: string }>> {
  const state = await getTwoFactorState();
  if (state.enabled) {
    return { ok: false, status: 409, error: "Two-factor authentication is already enabled" };
  }
  const secret = generateSecret();
  await updateSettings({ [SECRET_KEY]: encryptTotpSecret(secret) });
  return { ok: true, secret, otpauthUri: buildOtpauthUri(secret, account, ISSUER) };
}

/** Turn on 2FA: requires the management password AND a valid first TOTP code. */
export async function enableTwoFactor(input: {
  password: unknown;
  code: unknown;
}): Promise<TwoFactorResult<{ recoveryCodes: string[] }>> {
  if (!(await verifyPasswordReauth(input.password))) {
    return { ok: false, status: 401, error: "Invalid password" };
  }
  const state = await getTwoFactorState();
  if (state.enabled) {
    return { ok: false, status: 409, error: "Two-factor authentication is already enabled" };
  }
  if (!state.secret) {
    return { ok: false, status: 400, error: "No pending secret. Run setup first." };
  }
  const code = typeof input.code === "string" ? input.code.trim() : "";
  if (!verifyTotp(base32Decode(state.secret), code)) {
    return { ok: false, status: 401, error: "Invalid authentication code" };
  }
  const recoveryCodes = generateRecoveryCodes(RECOVERY_CODE_COUNT);
  await updateSettings({
    [ENABLED_KEY]: true,
    [RECOVERY_KEY]: recoveryCodes.map(hashRecoveryCode),
  });
  return { ok: true, recoveryCodes };
}

/** Turn off 2FA: requires the management password AND a valid second factor. */
export async function disableTwoFactor(input: {
  password: unknown;
  code: unknown;
}): Promise<TwoFactorResult> {
  if (!(await verifyPasswordReauth(input.password))) {
    return { ok: false, status: 401, error: "Invalid password" };
  }
  const state = await getTwoFactorState();
  if (!state.enabled) {
    return { ok: false, status: 409, error: "Two-factor authentication is not enabled" };
  }
  const code = typeof input.code === "string" ? input.code.trim() : "";
  const verdict = await verifySecondFactor(code, state);
  if (!verdict.ok) {
    return { ok: false, status: 401, error: "Invalid authentication code" };
  }
  await updateSettings({
    [ENABLED_KEY]: false,
    [SECRET_KEY]: "",
    [RECOVERY_KEY]: [],
  });
  return { ok: true };
}

export type SecondFactorVerdict =
  { ok: true; usedRecovery: boolean } | { ok: false; error: string };

/**
 * Verify a submitted second factor. Digit codes go to TOTP, anything else is
 * treated as a recovery code (single-use). `state` may be passed in to avoid a
 * second settings read on the login hot path.
 */
export async function verifySecondFactor(
  code: string,
  state?: TwoFactorState
): Promise<SecondFactorVerdict> {
  const current = state ?? (await getTwoFactorState());
  if (!current.enabled) {
    return { ok: false, error: "Two-factor authentication is not enabled" };
  }
  const normalized = typeof code === "string" ? code.trim() : "";
  if (!normalized) {
    return { ok: false, error: "Authentication code is required" };
  }

  if (/^\d{6}$/.test(normalized)) {
    if (!current.secret) {
      return { ok: false, error: "Invalid authentication code" };
    }
    if (verifyTotp(base32Decode(current.secret), normalized)) {
      return { ok: true, usedRecovery: false };
    }
    return { ok: false, error: "Invalid authentication code" };
  }

  const store = new Map<string, string>(current.recoveryCodes.map((hash) => [hash, hash]));
  if (consumeRecoveryCode(store, normalized)) {
    const outstanding = [...store.keys()];
    await updateSettings({ [RECOVERY_KEY]: outstanding });
    return { ok: true, usedRecovery: true };
  }
  return { ok: false, error: "Invalid authentication code" };
}

// ─── Pending login token ──────────────────────────────────────────────────────

/**
 * Pending tokens are signed with HMAC(JWT_SECRET, context) instead of
 * JWT_SECRET itself, so a pending token planted in the `auth_token` cookie
 * fails signature verification and cannot bypass the second factor.
 */
function getPendingKey(): Buffer | null {
  const secret = process.env.JWT_SECRET?.trim();
  if (!secret) return null;
  return createHmac("sha256", secret).update(PENDING_TOKEN_CONTEXT).digest();
}

export async function signPendingTwoFactorToken(
  options: { expSeconds?: number } = {}
): Promise<string> {
  const key = getPendingKey();
  if (!key) {
    throw new Error("JWT_SECRET is not set — cannot issue a 2FA challenge");
  }
  const expSeconds = options.expSeconds ?? PENDING_TOKEN_TTL_SECONDS;
  const nowSeconds = Math.floor(Date.now() / 1000);
  return new SignJWT({ purpose: PENDING_TOKEN_CONTEXT })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(nowSeconds)
    .setExpirationTime(nowSeconds + expSeconds)
    .sign(key);
}

export async function verifyPendingTwoFactorToken(token: unknown): Promise<boolean> {
  if (typeof token !== "string" || !token) return false;
  const key = getPendingKey();
  if (!key) return false;
  try {
    const { payload } = await jwtVerify(token, key);
    return payload.purpose === PENDING_TOKEN_CONTEXT;
  } catch {
    return false;
  }
}
