import { NextResponse } from "next/server";
import pino from "pino";

import { buildErrorBody } from "@omniroute/open-sse/utils/error.ts";

import { getProviderMetrics, type ProviderMetricRow } from "@/lib/db/callLogStats";
import { foldMetricRowsByFamily } from "@/lib/providerFamilyAgg";
import { toNumber, toNumberOrNull } from "@/shared/utils/numeric";

const logger = pino({ name: "provider-metrics-api" });
// sulashop: safe provider id for topology nodes (historical combo logs put candidate lists in provider column)
const SAFE_TOPOLOGY_PROVIDER_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

interface ProviderMetric {
  totalRequests: number;
  totalSuccesses: number;
  successRate: number;
  avgLatencyMs: number | null;
  lastRequestAt: string | null;
  lastErrorAt: string | null;
  lastStatus: number | null;
  lastErrorStatus: number | null;
  lastModel: string | null;
}

function toProviderMetric(row: ProviderMetricRow): ProviderMetric {
  const totalRequests = toNumber(row.totalRequests);
  const totalSuccesses = toNumber(row.totalSuccesses);
  return {
    totalRequests,
    totalSuccesses,
    successRate: totalRequests > 0 ? Math.round((totalSuccesses / totalRequests) * 100) : 0,
    avgLatencyMs: toNumberOrNull(row.avgLatencyMs),
    lastRequestAt: typeof row.lastRequestAt === "string" ? row.lastRequestAt : null,
    lastErrorAt: typeof row.lastErrorAt === "string" ? row.lastErrorAt : null,
    lastStatus: row.lastStatus == null ? null : toNumber(row.lastStatus),
    lastErrorStatus: row.lastErrorStatus == null ? null : toNumber(row.lastErrorStatus),
    lastModel: typeof row.lastModel === "string" ? row.lastModel : null,
  };
}

/**
 * GET /api/provider-metrics — Aggregate per-provider stats from call_logs
 * Returns per-provider metrics, per-family aggregates (`familyMetrics`) and
 * topology recency/error hints for dashboard visualization.
 */
export async function GET() {
  try {
    const rows = getProviderMetrics();

    const metrics: Record<string, ProviderMetric> = {};
    let lastProvider = "";
    let lastProviderTs = 0;
    let errorProvider = "";
    let errorProviderTs = 0;

    for (const row of rows) {
      const provider =
        typeof row.provider === "string" && row.provider.trim().length > 0
          ? row.provider
          : "unknown";
      // sulashop: Historical combo logs could store a comma-separated candidate/model list
      // in the provider column. Those are not provider identities and used to explode
      // the topology into one apparent node per model.
      if (!SAFE_TOPOLOGY_PROVIDER_ID.test(provider)) continue;
      const metric = toProviderMetric(row);
      metrics[provider] = metric;
      const { lastRequestAt, lastErrorAt, lastStatus } = metric;

      const requestTs = lastRequestAt ? Date.parse(lastRequestAt) : 0;
      if (Number.isFinite(requestTs) && requestTs > lastProviderTs) {
        lastProvider = provider;
        lastProviderTs = requestTs;
      }

      // Only flag as errorProvider if the provider's MOST RECENT request was itself
      // a failure. A provider with a historical lastErrorAt but a recent success
      // (lastStatus 2xx/3xx) must not be shown as currently errored (#3619).
      const isCurrentlyInError = lastStatus !== null && (lastStatus < 200 || lastStatus >= 400);
      const errorTs = isCurrentlyInError && lastErrorAt ? Date.parse(lastErrorAt) : 0;
      if (Number.isFinite(errorTs) && errorTs > errorProviderTs) {
        errorProvider = provider;
        errorProviderTs = errorTs;
      }
    }

    // Per-member rows stay in `metrics` (one per topology node); connection
    // families (e.g. kimi-coding + kimi-coding-apikey) get their folded totals
    // under `familyMetrics`, keyed by the canonical id (#15005).
    const familyMetrics = Object.fromEntries(
      foldMetricRowsByFamily(rows).map((row) => [row.provider, toProviderMetric(row)])
    );

    return NextResponse.json({
      metrics,
      familyMetrics,
      topology: {
        providers: Object.keys(metrics),
        lastProvider,
        lastModel: lastProvider ? metrics[lastProvider]?.lastModel || "" : "",
        errorProvider,
      },
    });
  } catch (error) {
    logger.error({ err: error }, "Failed to load provider metrics");
    return NextResponse.json(buildErrorBody(500, "Failed to load provider metrics"), {
      status: 500,
    });
  }
}
