import { NextResponse } from "next/server";
import { requireManagementAuth } from "@/lib/api/requireManagementAuth";
import { getTwoFactorState } from "@/lib/auth/twoFactor";

/**
 * GET /api/auth/2fa/status — dashboard 2FA enrollment state.
 *
 * Requires a management session (cookie / manage-scope key): the flag values
 * are harmless on their own, but the endpoint must not advertise the second
 * factor's existence to unauthenticated callers.
 */
export async function GET(request) {
  const authError = await requireManagementAuth(request);
  if (authError) return authError;

  try {
    const state = await getTwoFactorState();
    return NextResponse.json({ enabled: state.enabled, provisioned: state.provisioned });
  } catch (error) {
    console.error("[AUTH] 2FA status failed:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
