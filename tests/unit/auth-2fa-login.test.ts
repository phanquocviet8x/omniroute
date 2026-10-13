import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SignJWT } from "jose";

/**
 * RED contract for dashboard 2FA (TOTP) on the password login path.
 *
 * Scope agreed for OmniRoute: the web password login only. API keys, OIDC and
 * /api/cli/connect keep their existing behaviour.
 *
 * Non-negotiable invariant under test: a "pending 2FA" token must NEVER be
 * usable as an `auth_token` session (isDashboardSessionAuthenticated only
 * checks jwtVerify, so the pending token has to be signed with a derived key).
 */

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-2fa-"));
process.env.DATA_DIR = TEST_DATA_DIR;
process.env.JWT_SECRET = "test-jwt-secret-for-2fa-route";

const core = await import("../../src/lib/db/core.ts");
const settingsDb = await import("../../src/lib/db/settings.ts");
const managementPassword = await import("../../src/lib/auth/managementPassword.ts");
const totp = await import("../../src/lib/auth/totp.ts");
const twoFactor = await import("../../src/lib/auth/twoFactor.ts");
const apiAuth = await import("../../src/shared/utils/apiAuth.ts");
const publicRoutes = await import("../../src/shared/constants/publicApiRoutes.ts");
const classify = await import("../../src/server/authz/classify.ts");

const loginRoute = await import("../../src/app/api/auth/login/route.ts");
const verifyRoute = await import("../../src/app/api/auth/2fa/verify/route.ts");
const setupRoute = await import("../../src/app/api/auth/2fa/setup/route.ts");
const enableRoute = await import("../../src/app/api/auth/2fa/enable/route.ts");
const disableRoute = await import("../../src/app/api/auth/2fa/disable/route.ts");
const statusRoute = await import("../../src/app/api/auth/2fa/status/route.ts");
const settingsRoute = await import("../../src/app/api/settings/route.ts");

const PASSWORD = "correct-horse-battery-staple";
let ipCounter = 0;

/** Fresh client IP per test so the in-memory brute-force guard cannot bleed. */
function nextIp() {
  ipCounter += 1;
  return `10.9.${Math.floor(ipCounter / 250)}.${(ipCounter % 250) + 1}`;
}

function jsonRequest(url: string, body: unknown, headers: Record<string, string> = {}) {
  return new Request(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

/** Cookie-capturing fake cookie store for the route internals seams. */
function captureCookies() {
  const calls: Array<[string, string, Record<string, unknown>]> = [];
  return {
    calls,
    store: async () => ({
      set: (...args: unknown[]) => {
        calls.push(args as [string, string, Record<string, unknown>]);
      },
      delete: () => {},
    }),
    authCookies: () => calls.filter(([name]) => name === "auth_token"),
  };
}

async function mintSessionCookie(): Promise<string> {
  const token = await new SignJWT({ authenticated: true })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("30d")
    .sign(new TextEncoder().encode(process.env.JWT_SECRET));
  return `auth_token=${token}`;
}

/** Configure the management password without going through onboarding. */
async function seedPassword() {
  await settingsDb.updateSettings({
    password: await managementPassword.hashManagementPassword(PASSWORD),
  });
}

/** Full enrollment: provision secret → verify a real TOTP → enabled + recovery codes. */
async function enrollTwoFactor() {
  const provisioned = await setupRoute.POST(
    jsonRequest("http://localhost/api/auth/2fa/setup", { password: PASSWORD })
  );
  assert.equal(provisioned.status, 200, "setup failed");
  const { secret, otpauthUri } = await provisioned.json();
  assert.match(otpauthUri, /^otpauth:\/\/totp\//);

  const nowSeconds = Math.floor(Date.now() / 1000);
  const code = totp.totp(totp.base32Decode(secret), { atSeconds: nowSeconds });
  const enabled = await enableRoute.POST(
    jsonRequest("http://localhost/api/auth/2fa/enable", { password: PASSWORD, code })
  );
  assert.equal(enabled.status, 200, "enable failed");
  const { recoveryCodes } = await enabled.json();
  assert.equal(recoveryCodes.length, 10);
  return { secret, recoveryCodes };
}

async function login(password: string, ip: string) {
  return loginRoute.POST(
    jsonRequest("http://localhost/api/auth/login", { password }, { "x-forwarded-for": ip })
  );
}

test.beforeEach(async () => {
  core.resetDbInstance();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
  delete process.env.INITIAL_PASSWORD;
});

test.after(() => {
  core.resetDbInstance();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
});

// ── Enrollment ────────────────────────────────────────────────────────────────

test("2FA status route requires management auth", async () => {
  await seedPassword();
  const anonymous = await statusRoute.GET(new Request("http://localhost/api/auth/2fa/status"));
  assert.ok([401, 403].includes(anonymous.status), `got ${anonymous.status}`);

  const authed = await statusRoute.GET(
    new Request("http://localhost/api/auth/2fa/status", {
      headers: { cookie: await mintSessionCookie() },
    })
  );
  assert.equal(authed.status, 200);
  assert.deepEqual(await authed.json(), { enabled: false, provisioned: false });
});

test("setup requires the current password and stores the secret encrypted at rest", async () => {
  await seedPassword();
  const wrongPassword = await setupRoute.POST(
    jsonRequest("http://localhost/api/auth/2fa/setup", { password: "nope" })
  );
  assert.equal(wrongPassword.status, 401);

  const ok = await setupRoute.POST(
    jsonRequest("http://localhost/api/auth/2fa/setup", { password: PASSWORD })
  );
  assert.equal(ok.status, 200);
  const { secret, otpauthUri } = await ok.json();
  assert.match(secret, /^[A-Z2-7]{32}$/);
  assert.ok(otpauthUri.includes(`secret=${secret}`));

  // At rest: raw key_value row must not hold the plaintext secret.
  const row = core
    .getDbInstance()
    .prepare("SELECT value FROM key_value WHERE namespace = 'settings' AND key = 'twoFactorSecret'")
    .get() as { value: string } | undefined;
  assert.ok(row, "secret must be persisted");
  assert.equal(row!.value.includes(secret), false, "plaintext secret must not be stored");

  // Provisioning alone must NOT turn 2FA on.
  const state = await twoFactor.getTwoFactorState();
  assert.equal(state.enabled, false);
});

test("enable requires password + valid code; a wrong code keeps 2FA off", async () => {
  await seedPassword();
  const provisioned = await setupRoute.POST(
    jsonRequest("http://localhost/api/auth/2fa/setup", { password: PASSWORD })
  );
  const { secret } = await provisioned.json();
  const decoded = totp.base32Decode(secret);

  const wrongPassword = await enableRoute.POST(
    jsonRequest("http://localhost/api/auth/2fa/enable", { password: "nope", code: "000000" })
  );
  assert.equal(wrongPassword.status, 401);
  assert.equal((await twoFactor.getTwoFactorState()).enabled, false);

  const wrongCode = await enableRoute.POST(
    jsonRequest("http://localhost/api/auth/2fa/enable", {
      password: PASSWORD,
      code: totp.totp(decoded, { atSeconds: Math.floor(Date.now() / 1000) - 120 }),
    })
  );
  assert.ok([400, 401].includes(wrongCode.status), `got ${wrongCode.status}`);
  assert.equal((await twoFactor.getTwoFactorState()).enabled, false, "stale code must not enroll");

  const ok = await enableRoute.POST(
    jsonRequest("http://localhost/api/auth/2fa/enable", {
      password: PASSWORD,
      code: totp.totp(decoded, { atSeconds: Math.floor(Date.now() / 1000) }),
    })
  );
  assert.equal(ok.status, 200);
  const { recoveryCodes } = await ok.json();
  assert.equal(recoveryCodes.length, 10);
  assert.equal((await twoFactor.getTwoFactorState()).enabled, true);
});

// ── Login challenge ───────────────────────────────────────────────────────────

test("login without 2FA keeps the existing cookie flow", async () => {
  await seedPassword();
  const capture = captureCookies();
  const originalStore = loginRoute.authRouteInternals.getCookieStore;
  loginRoute.authRouteInternals.getCookieStore = capture.store;
  try {
    const response = await login(PASSWORD, nextIp());
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { success: true });
    assert.equal(capture.authCookies().length, 1);
    assert.equal(capture.authCookies()[0][0], "auth_token");
  } finally {
    loginRoute.authRouteInternals.getCookieStore = originalStore;
  }
});

test("login with 2FA enabled returns a pending token and sets NO session cookie", async () => {
  await seedPassword();
  await enrollTwoFactor();

  const capture = captureCookies();
  const originalStore = loginRoute.authRouteInternals.getCookieStore;
  loginRoute.authRouteInternals.getCookieStore = capture.store;
  try {
    const response = await login(PASSWORD, nextIp());
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.requires2FA, true);
    assert.equal(typeof body.token, "string");
    assert.equal(body.success, undefined, "must not claim success before the code is checked");
    assert.equal(capture.authCookies().length, 0, "no auth_token before the second factor");
  } finally {
    loginRoute.authRouteInternals.getCookieStore = originalStore;
  }
});

test("wrong password still fails even when 2FA is enabled", async () => {
  await seedPassword();
  await enrollTwoFactor();
  const response = await login("wrong-password", nextIp());
  assert.equal(response.status, 401);
});

test("pending 2FA token is NOT a valid dashboard session (cookie-injection bypass)", async () => {
  await seedPassword();
  await enrollTwoFactor();

  const response = await login(PASSWORD, nextIp());
  const { token } = await response.json();

  const authenticated = await apiAuth.isDashboardSessionAuthenticated({
    headers: new Headers({ cookie: `auth_token=${token}` }),
    url: "http://localhost/api/settings",
  });
  assert.equal(authenticated, false, "pending token must not authenticate a management route");

  // Sanity: a real session cookie still authenticates.
  const real = await mintSessionCookie();
  const realAuthed = await apiAuth.isDashboardSessionAuthenticated({
    headers: new Headers({ cookie: real }),
    url: "http://localhost/api/settings",
  });
  assert.equal(realAuthed, true);
});

// ── Second-factor verification ────────────────────────────────────────────────

test("verify accepts a valid TOTP and mints the session cookie", async () => {
  await seedPassword();
  const { secret } = await enrollTwoFactor();

  const loginResponse = await login(PASSWORD, nextIp());
  const { token } = await loginResponse.json();

  const capture = captureCookies();
  const originalStore = verifyRoute.verify2faRouteInternals.getCookieStore;
  verifyRoute.verify2faRouteInternals.getCookieStore = capture.store;
  try {
    const code = totp.totp(totp.base32Decode(secret), {
      atSeconds: Math.floor(Date.now() / 1000),
    });
    const result = await verifyRoute.POST(
      jsonRequest("http://localhost/api/auth/2fa/verify", { token, code })
    );
    assert.equal(result.status, 200, "verify failed");
    assert.deepEqual(await result.json(), { success: true });
    assert.equal(capture.authCookies().length, 1);
    const [name, , options] = capture.authCookies()[0];
    assert.equal(name, "auth_token");
    assert.equal(options.httpOnly, true);
    assert.equal(options.path, "/");
    assert.equal(options.maxAge, 60 * 60 * 24 * 30);
  } finally {
    verifyRoute.verify2faRouteInternals.getCookieStore = originalStore;
  }
});

test("verify rejects a wrong code and never sets a cookie", async () => {
  await seedPassword();
  await enrollTwoFactor();

  const { token } = await (await login(PASSWORD, nextIp())).json();
  const capture = captureCookies();
  const originalStore = verifyRoute.verify2faRouteInternals.getCookieStore;
  verifyRoute.verify2faRouteInternals.getCookieStore = capture.store;
  try {
    const result = await verifyRoute.POST(
      jsonRequest("http://localhost/api/auth/2fa/verify", { token, code: "000000" })
    );
    assert.equal(result.status, 401);
    assert.equal(capture.authCookies().length, 0);
  } finally {
    verifyRoute.verify2faRouteInternals.getCookieStore = originalStore;
  }
});

test("verify rejects malformed bodies, foreign tokens and expired tokens", async () => {
  await seedPassword();
  const { secret } = await enrollTwoFactor();
  const code = totp.totp(totp.base32Decode(secret), { atSeconds: Math.floor(Date.now() / 1000) });
  const capture = captureCookies();
  const originalStore = verifyRoute.verify2faRouteInternals.getCookieStore;
  verifyRoute.verify2faRouteInternals.getCookieStore = capture.store;
  try {
    const malformed = await verifyRoute.POST(
      jsonRequest("http://localhost/api/auth/2fa/verify", { code })
    );
    assert.equal(malformed.status, 400);

    // A regular auth_token (signed with the raw JWT_SECRET) must not pass as a pending token.
    const foreign = await verifyRoute.POST(
      jsonRequest("http://localhost/api/auth/2fa/verify", {
        token: await mintSessionCookie().then((c) => c.replace("auth_token=", "")),
        code,
      })
    );
    assert.equal(foreign.status, 401);

    // Expired pending token (signed with the derived key, exp in the past).
    const { signPendingTwoFactorToken } = await import("../../src/lib/auth/twoFactor.ts");
    const expired = await signPendingTwoFactorToken({ expSeconds: -60 });
    const expiredResponse = await verifyRoute.POST(
      jsonRequest("http://localhost/api/auth/2fa/verify", { token: expired, code })
    );
    assert.equal(expiredResponse.status, 401);

    assert.equal(capture.authCookies().length, 0, "no cookie for any rejected attempt");
  } finally {
    verifyRoute.verify2faRouteInternals.getCookieStore = originalStore;
  }
});

test("verify locks out after repeated failures (brute-force guard)", async () => {
  await seedPassword();
  await enrollTwoFactor();

  const ip = nextIp();
  const { token } = await (await login(PASSWORD, ip)).json();

  const statuses: number[] = [];
  for (let attempt = 0; attempt < 6; attempt++) {
    const response = await verifyRoute.POST(
      jsonRequest(
        "http://localhost/api/auth/2fa/verify",
        { token, code: "000000" },
        { "x-forwarded-for": ip }
      )
    );
    statuses.push(response.status);
  }
  assert.deepEqual(statuses.slice(0, 5), [401, 401, 401, 401, 401]);
  assert.equal(statuses[5], 429, "6th consecutive failure must be rate-limited");
});

test("a recovery code works exactly once", async () => {
  await seedPassword();
  const { recoveryCodes } = await enrollTwoFactor();

  const { token } = await (await login(PASSWORD, nextIp())).json();
  const capture = captureCookies();
  const originalStore = verifyRoute.verify2faRouteInternals.getCookieStore;
  verifyRoute.verify2faRouteInternals.getCookieStore = capture.store;
  try {
    const first = await verifyRoute.POST(
      jsonRequest("http://localhost/api/auth/2fa/verify", { token, code: recoveryCodes[0] })
    );
    assert.equal(first.status, 200, "recovery verify failed");
    assert.equal(capture.authCookies().length, 1);

    const second = await verifyRoute.POST(
      jsonRequest("http://localhost/api/auth/2fa/verify", {
        token,
        code: recoveryCodes[0],
      })
    );
    assert.equal(second.status, 401, "recovery codes are single-use");
  } finally {
    verifyRoute.verify2faRouteInternals.getCookieStore = originalStore;
  }
});

// ── Disable ───────────────────────────────────────────────────────────────────

test("disable requires password + code and restores the single-factor flow", async () => {
  await seedPassword();
  const { secret } = await enrollTwoFactor();
  const code = totp.totp(totp.base32Decode(secret), { atSeconds: Math.floor(Date.now() / 1000) });

  const wrongPassword = await disableRoute.POST(
    jsonRequest("http://localhost/api/auth/2fa/disable", { password: "nope", code })
  );
  assert.equal(wrongPassword.status, 401);
  assert.equal((await twoFactor.getTwoFactorState()).enabled, true);

  const ok = await disableRoute.POST(
    jsonRequest("http://localhost/api/auth/2fa/disable", { password: PASSWORD, code })
  );
  assert.equal(ok.status, 200, "disable failed");
  const state = await twoFactor.getTwoFactorState();
  assert.equal(state.enabled, false);
  assert.equal(state.secret, "", "secret must be wiped on disable");

  const capture = captureCookies();
  const originalStore = loginRoute.authRouteInternals.getCookieStore;
  loginRoute.authRouteInternals.getCookieStore = capture.store;
  try {
    const response = await login(PASSWORD, nextIp());
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { success: true });
    assert.equal(capture.authCookies().length, 1, "back to single-factor login");
  } finally {
    loginRoute.authRouteInternals.getCookieStore = originalStore;
  }
});

// ── Route classification + secret hygiene ─────────────────────────────────────

test("only the verify endpoint bypasses the dashboard cookie gate", () => {
  assert.equal(publicRoutes.isPublicApiRoute("/api/auth/2fa/verify", "POST"), true);
  assert.equal(publicRoutes.isPublicApiRoute("/api/auth/2fa/setup", "POST"), false);
  assert.equal(publicRoutes.isPublicApiRoute("/api/auth/2fa/enable", "POST"), false);
  assert.equal(publicRoutes.isPublicApiRoute("/api/auth/2fa/disable", "POST"), false);
  assert.equal(publicRoutes.isPublicApiRoute("/api/auth/2fa/status", "GET"), false);

  assert.equal(classify.classifyRoute("/api/auth/2fa/verify", "POST").routeClass, "PUBLIC");
  assert.equal(classify.classifyRoute("/api/auth/2fa/setup", "POST").routeClass, "MANAGEMENT");
});

test("settings API never exposes the TOTP secret or recovery hashes", async () => {
  await seedPassword();
  await enrollTwoFactor();

  const response = await settingsRoute.GET(
    new Request("http://localhost/api/settings", {
      headers: { cookie: await mintSessionCookie() },
    })
  );
  assert.equal(response.status, 200, "settings GET failed");
  const body = await response.json();
  const serialized = JSON.stringify(body.settings ?? body);
  assert.equal(serialized.includes("twoFactorSecret"), false);
  assert.equal(serialized.includes("twoFactorRecoveryCodes"), false);
  assert.equal(body.twoFactorEnabled, true, "the enabled flag stays visible");
});
