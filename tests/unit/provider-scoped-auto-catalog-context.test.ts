import test from "node:test";
import assert from "node:assert/strict";

import { appendProviderScopedAutoModels } from "../../src/app/api/v1/models/providerScopedAutoCatalog.ts";

test("provider-scoped auto catalog advertises the provider's largest context window", () => {
  const models = [
    {
      id: "apimode/small",
      root: "small",
      owned_by: "apimode",
      context_length: 128_000,
      max_output_tokens: 8_192,
    },
    {
      id: "apimode/gpt-5.6-sol",
      root: "gpt-5.6-sol",
      owned_by: "apimode",
      context_length: 1_050_000,
      max_output_tokens: 128_000,
    },
  ];

  const result = appendProviderScopedAutoModels(models, 123);
  const auto = result.find((model) => model.id === "auto/provider/apimode");

  assert.ok(auto);
  assert.equal(auto.context_length, 1_050_000);
  assert.equal(auto.max_input_tokens, 1_050_000);
  assert.equal(auto.max_output_tokens, 128_000);
  assert.equal(auto.owned_by, "combo");
});

test("provider-scoped auto catalog skips unsafe and synthetic owners", () => {
  const result = appendProviderScopedAutoModels(
    [
      { id: "auto/vision", owned_by: "combo", context_length: 1_000_000 },
      { id: "bad/model", owned_by: "../bad", context_length: 1_000_000 },
      { id: "unknown/model", owned_by: "unknown", context_length: 1_000_000 },
    ],
    123
  );

  assert.equal(result.length, 3);
});

test("provider-scoped auto catalog is idempotent when a route already exists", () => {
  const existing = {
    id: "auto/provider/apimode",
    owned_by: "combo",
    context_length: 1_050_000,
  };
  const result = appendProviderScopedAutoModels(
    [existing, { id: "apimode/gpt", owned_by: "apimode", context_length: 1_050_000 }],
    123
  );

  assert.equal(result.filter((model) => model.id === existing.id).length, 1);
});
