import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { parseProviderScopedAutoModel } from "../../src/sse/handlers/autoRouting.ts";

const factorySource = readFileSync(
  fileURLToPath(new URL("../../open-sse/services/autoCombo/virtualFactory.ts", import.meta.url)),
  "utf8"
);

test("parses only safe auto/provider/<provider> routes", () => {
  assert.deepEqual(parseProviderScopedAutoModel("auto/provider/codex"), {
    providerScope: "codex",
  });
  assert.deepEqual(parseProviderScopedAutoModel("auto/provider/openai-compatible-demo"), {
    providerScope: "openai-compatible-demo",
  });
  assert.equal(parseProviderScopedAutoModel("auto/provider/"), null);
  assert.equal(parseProviderScopedAutoModel("auto/provider/codex/extra"), null);
  assert.equal(parseProviderScopedAutoModel("auto/provider/../codex"), null);
  assert.equal(parseProviderScopedAutoModel("auto/provider/CODEX"), null);
});

test("provider-scoped factory is a hard candidate-pool constraint", () => {
  assert.match(factorySource, /resolveProviderScopeIds\(/);
  assert.match(factorySource, /providerScopeIds\.has\(candidate\.provider\)/);
  assert.match(
    factorySource,
    /auto\/provider\/\$\{providerScope\} matched no connected candidates; returning an empty pool/
  );
  assert.match(
    factorySource,
    /const providerPool = \[\.\.\.new Set\(effectivePool\.map\(\(c\) => c\.provider\)\)\]/
  );
});

test("provider-scoped auto preserves eligible account allowlists", () => {
  assert.match(factorySource, /allowedConnectionIds = providerConnections/);
  assert.match(factorySource, /\? \{ allowedConnectionIds: candidate\.allowedConnectionIds \}/);
});
