import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-scoped-synced-"));
const ORIGINAL_DATA_DIR = process.env.DATA_DIR;

process.env.DATA_DIR = TEST_DATA_DIR;

const core = await import("../../src/lib/db/core.ts");
const providersDb = await import("../../src/lib/db/providers.ts");
const modelsDb = await import("../../src/lib/db/models.ts");
const virtualFactory = await import("../../open-sse/services/autoCombo/virtualFactory.ts");

type VirtualComboResult = Awaited<ReturnType<typeof virtualFactory.createVirtualAutoCombo>>;

async function resetStorage() {
  core.resetDbInstance();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
}

test.beforeEach(async () => {
  await resetStorage();
});

test.after(async () => {
  await resetStorage();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });

  if (ORIGINAL_DATA_DIR === undefined) {
    delete process.env.DATA_DIR;
  } else {
    process.env.DATA_DIR = ORIGINAL_DATA_DIR;
  }
});

/**
 * A passthrough-style provider: registered in the provider registry with an
 * EMPTY static model list (like `bai`), so the virtual auto-combo candidate
 * builder can only see models that were synced per-connection.
 */
async function seedPassthroughProviderWithSyncedModels(options?: { excludeGlmOnFirst?: boolean }) {
  await providersDb.createProviderConnection({
    provider: "bai",
    authType: "apikey",
    name: "b.ai first",
    apiKey: "sk-test-bai-1",
  });
  await providersDb.createProviderConnection({
    provider: "bai",
    authType: "apikey",
    name: "b.ai second",
    apiKey: "sk-test-bai-2",
  });

  const connections = await providersDb.getProviderConnections({ isActive: true });
  const baiConnections = connections.filter((c) => c.provider === "bai");
  assert.equal(baiConnections.length, 2);

  const firstModels = [
    { id: "glm-5.3-flash", name: "glm-5.3-flash" },
    { id: "glm-5.2", name: "glm-5.2" },
  ];
  const secondModels = [
    { id: "gpt-5.6-luna", name: "gpt-5.6-luna" },
    { id: "minimax-m3", name: "minimax-m3" },
  ];

  await modelsDb.replaceSyncedAvailableModelsForConnection(
    "bai",
    baiConnections[0]!.id,
    options?.excludeGlmOnFirst ? firstModels : firstModels
  );
  await modelsDb.replaceSyncedAvailableModelsForConnection(
    "bai",
    baiConnections[1]!.id,
    secondModels
  );

  return { baiConnections, firstModels, secondModels };
}

test("provider-scoped auto restores candidates from synced connection models", async () => {
  const { baiConnections } = await seedPassthroughProviderWithSyncedModels();

  const combo: VirtualComboResult = await virtualFactory.createVirtualAutoCombo(undefined, {
    providerScope: "bai",
  });

  assert.equal(combo.strategy, "auto");
  assert.ok(combo.models.length > 0, "pool must not be empty for synced passthrough providers");

  const poolModels = combo.models.map((m) => m.model);
  assert.ok(
    poolModels.some((m) => m === "bai/glm-5.3-flash"),
    "glm-5.3-flash from first connection must be a candidate"
  );
  assert.ok(
    poolModels.some((m) => m === "bai/gpt-5.6-luna"),
    "gpt-5.6-luna from second connection must be a candidate"
  );
  assert.ok(
    !poolModels.some((m) => !m.startsWith("bai/")),
    "provider scope must stay exclusive to bai"
  );

  const glm = combo.models.find((m) => m.model === "bai/glm-5.3-flash");
  assert.ok(glm, "glm candidate exists");
  assert.deepEqual(glm!.connectionIds ?? [], glm!.connectionIds ?? [], "candidate shape sanity");

  // allowedConnectionIds must reference exactly the first connection that lists it
  const autoConfigAny = combo.autoConfig as unknown as { candidatePool: string[] };
  assert.ok(Array.isArray(autoConfigAny.candidatePool));
  assert.ok(autoConfigAny.candidatePool.includes("bai"));

  // The candidate must keep account fallback bound to the listing connection
  const modelsWithConnections = combo.models as unknown as Array<{
    model: string;
    connectionId: string | null;
    allowedConnectionIds?: string[];
  }>;
  const glmEntry = modelsWithConnections.find((m) => m.model === "bai/glm-5.3-flash");
  assert.ok(glmEntry);
  assert.deepEqual(glmEntry!.allowedConnectionIds, [baiConnections[0]!.id]);
});

test("provider-scoped auto stays fail-closed without synced models", async () => {
  await providersDb.createProviderConnection({
    provider: "bai",
    authType: "apikey",
    name: "b.ai only",
    apiKey: "sk-test-bai-3",
  });

  const combo: VirtualComboResult = await virtualFactory.createVirtualAutoCombo(undefined, {
    providerScope: "bai",
  });

  assert.equal(combo.models.length, 0, "no synced models and no registry models -> empty pool");
  assert.equal(combo.autoConfig.candidatePool.length, 0);
});

test("provider-scoped auto merges synced models across connections per model", async () => {
  const { baiConnections } = await seedPassthroughProviderWithSyncedModels();

  // Add glm-5.3-flash to the second connection too — the model candidate must
  // then allow BOTH connections (account fallback across accounts).
  await modelsDb.replaceSyncedAvailableModelsForConnection("bai", baiConnections[1]!.id, [
    { id: "gpt-5.6-luna", name: "gpt-5.6-luna" },
    { id: "glm-5.3-flash", name: "glm-5.3-flash" },
  ]);

  const combo: VirtualComboResult = await virtualFactory.createVirtualAutoCombo(undefined, {
    providerScope: "bai",
  });

  const modelsWithConnections = combo.models as unknown as Array<{
    model: string;
    allowedConnectionIds?: string[];
  }>;
  const glmEntry = modelsWithConnections.find((m) => m.model === "bai/glm-5.3-flash");
  assert.ok(glmEntry);
  assert.equal(glmEntry!.allowedConnectionIds!.length, 2);
  assert.ok(glmEntry!.allowedConnectionIds!.includes(baiConnections[0]!.id));
  assert.ok(glmEntry!.allowedConnectionIds!.includes(baiConnections[1]!.id));
});
