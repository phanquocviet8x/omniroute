type CatalogModelLike = {
  id?: string;
  owned_by?: string;
  context_length?: number;
  max_input_tokens?: number;
  max_output_tokens?: number;
  [key: string]: unknown;
};

const SAFE_PROVIDER_SCOPE_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const SYNTHETIC_OWNERS = new Set(["auto", "combo", "provider", "unknown"]);
const DEFAULT_CONTEXT_LENGTH = 128_000;
const DEFAULT_MAX_OUTPUT_TOKENS = 8_192;

/**
 * Advertise OmniRoute's dynamic `auto/provider/<provider>` contracts using the
 * largest context/output limits already visible for each key-filtered provider.
 * The auto router context-prefilters its candidate pool, so a large request is
 * dispatched only to a model that can actually hold it.
 */
export function appendProviderScopedAutoModels<T extends CatalogModelLike>(
  models: T[],
  timestamp: number
): Array<T | CatalogModelLike> {
  const existingIds = new Set(models.map((model) => model.id).filter(Boolean));
  const limits = new Map<string, { contextLength: number; maxOutputTokens: number }>();

  for (const model of models) {
    const provider = typeof model.owned_by === "string" ? model.owned_by.trim() : "";
    if (!SAFE_PROVIDER_SCOPE_RE.test(provider) || SYNTHETIC_OWNERS.has(provider)) continue;

    const current = limits.get(provider) ?? {
      contextLength: DEFAULT_CONTEXT_LENGTH,
      maxOutputTokens: DEFAULT_MAX_OUTPUT_TOKENS,
    };
    const contextLength = Number(model.context_length || model.max_input_tokens || 0);
    const maxOutputTokens = Number(model.max_output_tokens || 0);
    if (Number.isFinite(contextLength) && contextLength > current.contextLength) {
      current.contextLength = contextLength;
    }
    if (Number.isFinite(maxOutputTokens) && maxOutputTokens > current.maxOutputTokens) {
      current.maxOutputTokens = maxOutputTokens;
    }
    limits.set(provider, current);
  }

  const providerAutoModels: CatalogModelLike[] = [];
  for (const [provider, limit] of limits) {
    const id = `auto/provider/${provider}`;
    if (existingIds.has(id)) continue;
    providerAutoModels.push({
      id,
      object: "model",
      created: timestamp,
      owned_by: "combo",
      permission: [],
      root: id,
      parent: null,
      context_length: limit.contextLength,
      max_input_tokens: limit.contextLength,
      max_output_tokens: limit.maxOutputTokens,
      capabilities: {
        tool_calling: true,
        reasoning: true,
        thinking: true,
        temperature: true,
      },
    });
  }

  return [...models, ...providerAutoModels];
}
