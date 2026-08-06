import test from "node:test";
import assert from "node:assert/strict";

import { resolveProviderScopeIds } from "../../open-sse/services/autoCombo/providerScope.ts";

test("provider scope resolves a compatible-provider public prefix to its internal node id", () => {
  const ids = resolveProviderScopeIds("apimode", [
    {
      id: "openai-compatible-chat-750bdc30-cc64-4b1a-995b-16c82672e56f",
      prefix: "apimode",
    },
  ]);

  assert.deepEqual(
    ids,
    new Set(["apimode", "openai-compatible-chat-750bdc30-cc64-4b1a-995b-16c82672e56f"])
  );
});

test("provider scope matching is case-insensitive for configured prefixes", () => {
  const ids = resolveProviderScopeIds("apimode", [{ id: "node-1", prefix: "ApiMode" }]);
  assert.equal(ids.has("node-1"), true);
});

test("provider scope never admits an unrelated compatible-provider node", () => {
  const ids = resolveProviderScopeIds("apimode", [
    { id: "node-apikey", prefix: "apikey" },
    { id: "node-apimode", prefix: "apimode" },
  ]);

  assert.equal(ids.has("node-apimode"), true);
  assert.equal(ids.has("node-apikey"), false);
});
