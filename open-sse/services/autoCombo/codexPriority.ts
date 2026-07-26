/** Stable model-major ordering for every live Codex account/model candidate. */
const CODEX_FAMILY_ORDER = ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5"];
const EFFORT_ORDER = ["ultra", "max", "xhigh", "high", "medium", "low", ""];

export function getCodexModelPriority(model: string): number {
  if (model === "codex-auto-review") return 90_000;
  for (let familyIndex = 0; familyIndex < CODEX_FAMILY_ORDER.length; familyIndex += 1) {
    const family = CODEX_FAMILY_ORDER[familyIndex];
    if (model === family) return familyIndex * 100 + EFFORT_ORDER.indexOf("");
    if (!model.startsWith(`${family}-`)) continue;
    const effortIndex = EFFORT_ORDER.indexOf(model.slice(family.length + 1));
    return familyIndex * 100 + (effortIndex >= 0 ? effortIndex : 90);
  }
  const version = model.match(/^gpt-(\d+)\.(\d+)(?:-(.*))?$/);
  if (version) return 10_000 - Number(version[1]) * 100 - Number(version[2]);
  return 99_000;
}
