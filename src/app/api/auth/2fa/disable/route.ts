import { NextResponse } from "next/server";
import { getAuditRequestContext, logAuditEvent } from "@/lib/compliance/index";
import { disableTwoFactor } from "@/lib/auth/twoFactor";
import { twoFactorManageSchema } from "@/shared/validation/schemas";
import { isValidationFailure, validateBody } from "@/shared/validation/helpers";

/**
 * POST /api/auth/2fa/disable — turn 2FA off and wipe the secret.
 *
 * Requires the management password (re-auth) AND a currently valid second
 * factor, so a stolen password alone cannot silently remove the protection.
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

    const result = await disableTwoFactor({
      password: validation.data.password,
      code: validation.data.code,
    });
    if (!result.ok) {
      logAuditEvent({
        action: "auth.2fa.disable_failed",
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
      action: "auth.2fa.disable",
      actor: "dashboard",
      target: "dashboard-auth",
      resourceType: "auth_session",
      status: "success",
      ipAddress: auditContext.ipAddress || undefined,
      requestId: auditContext.requestId,
      metadata: {},
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("[AUTH] 2FA disable failed:", error);
    logAuditEvent({
      action: "auth.2fa.disable_error",
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
