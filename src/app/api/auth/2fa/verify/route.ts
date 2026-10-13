import { NextResponse } from "next/server";
import { SignJWT } from "jose";
import { cookies } from "next/headers";
import { getAuditRequestContext, logAuditEvent } from "@/lib/compliance/index";
import {
  getTwoFactorState,
  verifyPendingTwoFactorToken,
  verifySecondFactor,
} from "@/lib/auth/twoFactor";
import { twoFactorVerifySchema } from "@/shared/validation/schemas";
import { isValidationFailure, validateBody } from "@/shared/validation/helpers";
import { checkLoginGuard, clearLoginAttempts, recordLoginFailure } from "@/server/auth/loginGuard";

// Test seam for cookie store injection without affecting runtime behavior.
export const verify2faRouteInternals = {
  getCookieStore: cookies,
};

function getJwtSecret(): Uint8Array {
  return new TextEncoder().encode(process.env.JWT_SECRET || "");
}

/**
 * POST /api/auth/2fa/verify — complete a pending 2FA login.
 *
 * Public route (no session cookie yet): the caller presents the pending token
 * minted by POST /api/auth/login plus a valid second factor. On success the
 * standard `auth_token` session cookie is minted exactly like the single-factor
 * login path. Wrong codes are recorded per client IP: the first five failures
 * get 401, every subsequent attempt is rate-limited with 429.
 */
export async function POST(request) {
  const auditContext = getAuditRequestContext(request);

  try {
    if (!process.env.JWT_SECRET) {
      return NextResponse.json({ error: "Server misconfigured" }, { status: 500 });
    }

    let rawBody;
    try {
      rawBody = await request.json();
    } catch {
      return NextResponse.json(
        {
          error: {
            message: "Invalid request",
            details: [{ field: "body", message: "Invalid JSON body" }],
          },
        },
        { status: 400 }
      );
    }

    const validation = validateBody(twoFactorVerifySchema, rawBody);
    if (isValidationFailure(validation)) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    const bruteForceEnabled = (await getTwoFactorState()).enabled;
    const clientIp = auditContext.ipAddress || null;

    // Rate-limit the second factor per IP (5 wrong codes / 15 min → 429),
    // mirroring the password login guard.
    const guardCheck = checkLoginGuard(clientIp, { enabled: bruteForceEnabled });
    if (!guardCheck.allowed) {
      logAuditEvent({
        action: "auth.2fa.verify_locked",
        actor: "anonymous",
        target: "dashboard-auth",
        resourceType: "auth_session",
        status: "failed",
        ipAddress: clientIp || undefined,
        requestId: auditContext.requestId,
        metadata: { retryAfterSeconds: guardCheck.retryAfterSeconds || 0 },
      });
      return NextResponse.json(
        { error: "Too many failed attempts. Try again later." },
        {
          status: 429,
          headers: guardCheck.retryAfterSeconds
            ? { "Retry-After": String(guardCheck.retryAfterSeconds) }
            : {},
        }
      );
    }

    // The pending token proves the password step succeeded within its short
    // TTL. A regular auth_token (raw JWT_SECRET key) fails this check.
    if (!(await verifyPendingTwoFactorToken(validation.data.token))) {
      logAuditEvent({
        action: "auth.2fa.verify_failed",
        actor: "anonymous",
        target: "dashboard-auth",
        resourceType: "auth_session",
        status: "failed",
        ipAddress: auditContext.ipAddress || undefined,
        requestId: auditContext.requestId,
        metadata: { reason: "invalid_or_expired_pending_token" },
      });
      return NextResponse.json(
        { error: "Invalid or expired login session. Log in again." },
        { status: 401 }
      );
    }

    const state = await getTwoFactorState();
    const verdict = await verifySecondFactor(validation.data.code, state);
    if (!verdict.ok) {
      const failureDecision = recordLoginFailure(clientIp, { enabled: bruteForceEnabled });
      logAuditEvent({
        action: "auth.2fa.verify_failed",
        actor: "anonymous",
        target: "dashboard-auth",
        resourceType: "auth_session",
        status: "failed",
        ipAddress: auditContext.ipAddress || undefined,
        requestId: auditContext.requestId,
        metadata: {
          reason: verdict.error,
          usedRecovery: false,
          lockedOut: failureDecision.allowed === false,
        },
      });
      // This failed attempt still gets a plain 401; the recorded failure makes
      // checkLoginGuard rate-limit every subsequent attempt with 429 (5 wrong
      // codes / 15 min window → lockout, same tunables as the login guard).
      return NextResponse.json({ error: verdict.error }, { status: 401 });
    }

    // Success — mint the standard 30-day session cookie (same contract as the
    // single-factor login path, including the Secure flag over HTTPS).
    const forceSecureCookie = process.env.AUTH_COOKIE_SECURE === "true";
    const forwardedProtoHeader = request.headers.get("x-forwarded-proto") || "";
    const forwardedProto = forwardedProtoHeader.split(",")[0].trim().toLowerCase();
    const isHttpsRequest = forwardedProto === "https" || request.nextUrl?.protocol === "https:";
    const useSecureCookie = forceSecureCookie || isHttpsRequest;

    const token = await new SignJWT({ authenticated: true })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("30d")
      .sign(getJwtSecret());

    const cookieStore = await verify2faRouteInternals.getCookieStore();
    cookieStore.set("auth_token", token, {
      httpOnly: true,
      secure: useSecureCookie,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 30,
    });

    logAuditEvent({
      action: "auth.2fa.verify",
      actor: "admin",
      target: "dashboard-auth",
      resourceType: "auth_session",
      status: "success",
      ipAddress: auditContext.ipAddress || undefined,
      requestId: auditContext.requestId,
      metadata: { usedRecovery: verdict.usedRecovery, secureCookie: useSecureCookie },
    });

    clearLoginAttempts(clientIp);
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("[AUTH] 2FA verify failed:", error);
    logAuditEvent({
      action: "auth.2fa.verify_error",
      actor: "system",
      target: "dashboard-auth",
      resourceType: "auth_session",
      status: "failed",
      ipAddress: auditContext.ipAddress || undefined,
      requestId: auditContext.requestId,
      metadata: { message: error instanceof Error ? error.message : "unknown_error" },
    });
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
