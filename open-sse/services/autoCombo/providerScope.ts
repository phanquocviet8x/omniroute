export type ProviderScopeNode = {
  id?: unknown;
  prefix?: unknown;
};

/** Resolve a public provider route scope to every matching internal provider id. */
export function resolveProviderScopeIds(
  providerScope: string,
  providerNodes: ProviderScopeNode[]
): Set<string> {
  const scope = providerScope.trim().toLowerCase();
  const ids = new Set<string>([providerScope]);

  for (const node of providerNodes) {
    const id = typeof node.id === "string" ? node.id.trim() : "";
    const prefix = typeof node.prefix === "string" ? node.prefix.trim().toLowerCase() : "";
    if (id && prefix === scope) ids.add(id);
  }

  return ids;
}
