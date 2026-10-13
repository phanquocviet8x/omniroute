"use client";

import { useState, useEffect, useCallback } from "react";
import { Card, Button, Input } from "@/shared/components";

/**
 * Dashboard 2FA (TOTP) management — enable / disable from the Security tab.
 *
 * Enrollment and disable both require the current management password (server
 * re-auth), so this component never mutates 2FA state through /api/settings.
 * Recovery codes are shown exactly once, right after a successful enable.
 */
export default function TwoFactorSection() {
  const [status, setStatus] = useState({ enabled: false, provisioned: false });
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  // Setup flow: password → secret/QR data → first code → recovery codes.
  const [flow, setFlow] = useState(null); // null | "setup" | "disable"
  const [setupPassword, setSetupPassword] = useState("");
  const [setupCode, setSetupCode] = useState("");
  const [secret, setSecret] = useState("");
  const [otpauthUri, setOtpauthUri] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState([]);

  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");

  const refreshStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/auth/2fa/status");
      if (res.ok) {
        setStatus(await res.json());
      }
    } catch {
      // leave defaults on failure; the section still renders
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  const resetFlow = () => {
    setFlow(null);
    setSetupPassword("");
    setSetupCode("");
    setSecret("");
    setOtpauthUri("");
    setDisablePassword("");
    setDisableCode("");
    setError("");
  };

  const startSetup = async () => {
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/auth/2fa/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: setupPassword }),
      });
      const data = await res.json();
      if (res.ok) {
        setSecret(data.secret);
        setOtpauthUri(data.otpauthUri);
      } else {
        setError(
          typeof data?.error === "string" ? data.error : data?.error?.message || "Setup failed"
        );
      }
    } catch {
      setError("Setup failed");
    } finally {
      setBusy(false);
    }
  };

  const confirmEnable = async () => {
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/auth/2fa/enable", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: setupPassword, code: setupCode.trim() }),
      });
      const data = await res.json();
      if (res.ok) {
        setRecoveryCodes(data.recoveryCodes || []);
        setStatus((prev) => ({ ...prev, enabled: true }));
        setNotice(
          "Two-factor authentication is now enabled. Save the recovery codes below — they are shown only once."
        );
      } else {
        setError(
          typeof data?.error === "string" ? data.error : data?.error?.message || "Invalid code"
        );
      }
    } catch {
      setError("Enable failed");
    } finally {
      setBusy(false);
    }
  };

  const confirmDisable = async () => {
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/auth/2fa/disable", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: disablePassword, code: disableCode.trim() }),
      });
      const data = await res.json();
      if (res.ok) {
        setStatus({ enabled: false, provisioned: false });
        setNotice("Two-factor authentication has been disabled.");
        resetFlow();
      } else {
        setError(
          typeof data?.error === "string"
            ? data.error
            : data?.error?.message || "Invalid password or code"
        );
      }
    } catch {
      setError("Disable failed");
    } finally {
      setBusy(false);
    }
  };

  const copy = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* clipboard unavailable — user can still select manually */
    }
  };

  return (
    <Card>
      <div className="flex items-center gap-3 mb-4">
        <div className="p-2 rounded-lg bg-green-500/10 text-green-600 dark:text-green-400">
          <span className="material-symbols-outlined text-[20px]" aria-hidden="true">
            verified_user
          </span>
        </div>
        <h3 className="text-lg font-semibold">Two-Factor Authentication (TOTP)</h3>
      </div>

      <div className="flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="font-medium">Authenticator app second factor</p>
            <p className="text-sm text-text-muted">
              {loading
                ? "Loading…"
                : status.enabled
                  ? "Enabled — the dashboard login asks for a 6-digit code after the password."
                  : "Disabled — add a TOTP app (Google Authenticator, Authy, 1Password…) as a second login factor."}
            </p>
          </div>
          {!loading && !status.enabled && !flow && (
            <Button
              variant="primary"
              onClick={() => {
                setFlow("setup");
                setNotice("");
                setError("");
              }}
              disabled={busy}
            >
              Enable 2FA
            </Button>
          )}
        </div>

        {notice && <p className="text-sm text-green-500">{notice}</p>}
        {error && <p className="text-sm text-red-500">{error}</p>}

        {flow === "setup" && !recoveryCodes.length && (
          <div className="flex flex-col gap-4 pt-4 border-t border-border/50">
            {!secret ? (
              <>
                <p className="text-sm text-text-muted">
                  Step 1 of 2 — confirm your current password to provision a TOTP secret.
                </p>
                <Input
                  label="Current password"
                  type="password"
                  value={setupPassword}
                  onChange={(e) => setSetupPassword(e.target.value)}
                  autoFocus
                  disabled={busy}
                />
                <div className="flex gap-2">
                  <Button
                    variant="primary"
                    onClick={startSetup}
                    loading={busy}
                    disabled={!setupPassword}
                  >
                    Continue
                  </Button>
                  <Button variant="ghost" onClick={resetFlow} disabled={busy}>
                    Cancel
                  </Button>
                </div>
              </>
            ) : (
              <>
                <p className="text-sm text-text-muted">
                  Step 2 of 2 — add the secret to your authenticator app, then enter the current
                  6-digit code to confirm.
                </p>
                <div className="rounded-lg border border-border/50 bg-black/[0.02] dark:bg-white/[0.02] p-3 text-sm">
                  <div className="flex items-center justify-between gap-2">
                    <code className="font-mono break-all">{secret}</code>
                    <Button variant="ghost" onClick={() => copy(secret)}>
                      Copy key
                    </Button>
                  </div>
                  <div className="flex items-center justify-between gap-2 mt-2">
                    <code className="font-mono break-all text-xs text-text-muted">
                      {otpauthUri}
                    </code>
                    <Button variant="ghost" onClick={() => copy(otpauthUri)}>
                      Copy URI
                    </Button>
                  </div>
                </div>
                <Input
                  label="6-digit code"
                  placeholder="123456"
                  value={setupCode}
                  onChange={(e) => setSetupCode(e.target.value)}
                  autoFocus
                  disabled={busy}
                  className="font-mono"
                />
                <div className="flex gap-2">
                  <Button
                    variant="primary"
                    onClick={confirmEnable}
                    loading={busy}
                    disabled={setupCode.trim().length < 6}
                  >
                    Enable
                  </Button>
                  <Button variant="ghost" onClick={resetFlow} disabled={busy}>
                    Cancel
                  </Button>
                </div>
              </>
            )}
          </div>
        )}

        {recoveryCodes.length > 0 && (
          <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-4">
            <p className="text-sm font-medium text-amber-600 dark:text-amber-400 mb-2">
              Recovery codes — each works exactly once, shown only now:
            </p>
            <div className="grid grid-cols-2 gap-1 font-mono text-sm">
              {recoveryCodes.map((code) => (
                <span key={code}>{code}</span>
              ))}
            </div>
            <div className="mt-3 flex gap-2">
              <Button variant="ghost" onClick={() => copy(recoveryCodes.join("\n"))}>
                Copy all
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  setRecoveryCodes([]);
                  resetFlow();
                }}
              >
                Done
              </Button>
            </div>
          </div>
        )}

        {flow === "disable" && (
          <div className="flex flex-col gap-4 pt-4 border-t border-border/50">
            <p className="text-sm text-text-muted">
              Disable 2FA — requires your password AND a currently valid code.
            </p>
            <Input
              label="Current password"
              type="password"
              value={disablePassword}
              onChange={(e) => setDisablePassword(e.target.value)}
              disabled={busy}
            />
            <Input
              label="6-digit code or recovery code"
              placeholder="123456 or ABCDE-FGHJK"
              value={disableCode}
              onChange={(e) => setDisableCode(e.target.value)}
              disabled={busy}
              className="font-mono"
            />
            <div className="flex gap-2">
              <Button
                variant="primary"
                onClick={confirmDisable}
                loading={busy}
                disabled={!disablePassword || !disableCode.trim()}
              >
                Disable
              </Button>
              <Button variant="ghost" onClick={resetFlow} disabled={busy}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {!loading && status.enabled && !flow && (
          <div className="pt-2">
            <Button
              variant="ghost"
              onClick={() => {
                setFlow("disable");
                setNotice("");
                setError("");
              }}
            >
              Disable 2FA
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}
