import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const read = (path) => fs.readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8");

test("custom channels use distinct non-upstream names", () => {
  const catalog = read("open-sse/services/autoCombo/builtinCatalog.ts");
  assert.match(catalog, /"auto\/bestfree": "cheap"/);
  assert.match(catalog, /"auto\/bestcodex": "coding"/);
  assert.match(catalog, /"auto\/best-free": "cheap"/);
});

test("request routing assigns strict policy only to custom channels", () => {
  const source = read("src/sse/handlers/autoRouting.ts");
  assert.match(source, /model === "auto\/bestfree"[\s\S]*?"free-first-paid-fallback"/);
  assert.match(source, /model === "auto\/bestcodex"[\s\S]*?"codex-paid-free"/);
});

test("free-first and Codex-first stages are preserved through execution ordering", () => {
  const resolver = read("open-sse/services/combo/resolveAutoStrategy.ts");
  assert.match(resolver, /routingPolicy === "free-first-paid-fallback"/);
  assert.match(resolver, /routingPolicy === "codex-paid-free"/);
  assert.match(resolver, /candidate\.provider === "codex"/);
  assert.match(resolver, /getCodexModelPriority\(candidate\.model\)/);
  assert.match(resolver, /routingPolicy \? rankedTargets\[0\]/);
  assert.match(resolver, /if \(routingPolicy\) autoUsedExplicitRouter = true/);
  const combo = read("open-sse/services/combo.ts");
  assert.match(combo, /autoPinnedTarget = autoUsedExplicitRouter \? orderedTargets\[0\]/);
  assert.match(combo, /Re-pin only when the strict-policy target survived/);
  assert.match(combo, /autoPinnedTarget = undefined;[\s\S]*?autoUsedExplicitRouter = false/);
});

test("custom policy keeps full pool for paid/free fallback", () => {
  const factory = read("open-sse/services/autoCombo/virtualFactory.ts");
  assert.match(factory, /spec\?\.category \|\| spec\?\.tier/);
  assert.match(factory, /routingPolicy: spec\.policy/);
});
