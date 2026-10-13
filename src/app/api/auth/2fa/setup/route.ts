import { NextResponse } from "next/server";
import { getAuditRequestContext, logAuditEvent } from "@/lib/compliance/index";
import { provisionTwoFactorSecret, verifyTwoFactorPassword } from "@/lib/auth/twoFactor";
import { twoFactorSetupSchema } from "@/shared/validation/schemas";
import { isValidationFailure, validateBody } from "@/shared/validation/helpers";

/**
 * POST /api/auth/2fa/setup — provision (or rotate) a pending TOTP secret.
 *
 * Authentication is the management password in the body (re-auth), not the
 * session cookie: enrollment must require proving knowledge of the password
 * even from an already-authenticated dashboard tab.
 */
export async function POST(request) {
  const auditContext = getAuditRequestContext(request);

  try {
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

    const validation = validateBody(twoFactorSetupSchema, rawBody);
    if (isValidationFailure(validation)) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    // Re-auth: provisioning a (rotating!) TOTP secret requires the current
    // management password, not just an existing dashboard session.
    if (!(await verifyTwoFactorPassword(validation.data.password))) {
      logAuditEvent({
        action: "auth.2fa.setup_failed",
        actor: "dashboard",
        target: "dashboard-auth",
        resourceType: "auth_session",
        status: "failed",
        ipAddress: auditContext.ipAddress || undefined,
        requestId: auditContext.requestId,
        metadata: { status: 401, reason: "Invalid password" },
      });
      return NextResponse.json({ error: "Invalid password" }, { status: 401 });
    }

    const result = await provisionTwoFactorSecret("dashboard");
    if (!result.ok) {
      logAuditEvent({
        action: "auth.2fa.setup_failed",
        actor: "dashboard",
        target: "dashboard-auth",
        resourceType: "auth_session",
        status: "failed",
        ipAddress: auditContext.ipAddress || undefined,
        requestId: auditContext.requestId,
        metadata: { status: result.status, reason: result.error },
      });
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    logAuditEvent({
      action: "auth.2fa.setup",
      actor: "dashboard",
      target: "dashboard-auth",
      resourceType: "auth_session",
      status: "success",
      ipAddress: auditContext.ipAddress || undefined,
      requestId: auditContext.requestId,
      metadata: {},
    });

    return NextResponse.json({ secret: result.secret, otpauthUri: result.otpauthUri });
  } catch (error) {
    console.error("[AUTH] 2FA setup failed:", error);
    logAuditEvent({
      action: "auth.2fa.setup_error",
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
