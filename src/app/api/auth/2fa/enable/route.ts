import { NextResponse } from "next/server";
import { getAuditRequestContext, logAuditEvent } from "@/lib/compliance/index";
import { enableTwoFactor } from "@/lib/auth/twoFactor";
import { twoFactorManageSchema } from "@/shared/validation/schemas";
import { isValidationFailure, validateBody } from "@/shared/validation/helpers";

/**
 * POST /api/auth/2fa/enable — confirm the first valid TOTP and turn 2FA on.
 *
 * Requires the management password (re-auth) AND a valid code from the
 * provisioned secret. Returns the one-time recovery codes exactly once.
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

    const validation = validateBody(twoFactorManageSchema, rawBody);
    if (isValidationFailure(validation)) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    const result = await enableTwoFactor({
      password: validation.data.password,
      code: validation.data.code,
    });
    if (!result.ok) {
      logAuditEvent({
        action: "auth.2fa.enable_failed",
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
      action: "auth.2fa.enable",
      actor: "dashboard",
      target: "dashboard-auth",
      resourceType: "auth_session",
      status: "success",
      ipAddress: auditContext.ipAddress || undefined,
      requestId: auditContext.requestId,
      metadata: { recoveryCodeCount: result.recoveryCodes.length },
    });

    return NextResponse.json({ recoveryCodes: result.recoveryCodes });
  } catch (error) {
    console.error("[AUTH] 2FA enable failed:", error);
    logAuditEvent({
      action: "auth.2fa.enable_error",
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
