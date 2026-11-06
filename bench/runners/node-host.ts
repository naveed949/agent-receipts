import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

type Role = "typescript" | "node_napi";

interface HostApi {
  canonicalJson(value: unknown): string;
  stableHash(value: unknown): string;
  verifyAuditReceipt(receipt: unknown, key: unknown): boolean;
  verifyControlledIntegrity(
    value: unknown,
    key: unknown,
    keyId: string,
    evidence: unknown,
  ): boolean;
  compareAuthorityContracts(
    previous: unknown,
    next: unknown,
  ): { relationship: string; widened: string[]; narrowed: string[] };
}

interface PlanCase {
  operation: string;
  caseId: unknown;
  warmup: number;
  iterations: number;
  payload: unknown;
}

try {
  await main();
} catch (err) {
  console.error(err instanceof Error ? (err.stack ?? err.message) : String(err));
  process.exit(1);
}

async function main(): Promise<void> {
  const role = process.argv[2];
  if (role !== "typescript" && role !== "node_napi") {
    throw new Error("role");
  }
  const api = await loadApi(role);
  const plan = JSON.parse(readFileSync(0, "utf8")) as {
    schema?: unknown;
    cases?: PlanCase[];
  };
  if (plan.schema !== 1 || !Array.isArray(plan.cases)) {
    throw new Error("plan");
  }
  const probes = [];
  const samples = [];
  for (const item of plan.cases) {
    const call = bind(api, item.operation, item.payload);
    probes.push({
      operation: item.operation,
      caseId: item.caseId,
      observed: normalize(item.operation, call()),
    });
    samples.push({
      operation: item.operation,
      caseId: item.caseId,
      ns: timeLoop(item.warmup, item.iterations, call, item.operation),
    });
  }
  process.stdout.write(`${JSON.stringify({ schema: 1, probes, samples })}\n`);
}

function bind(host: HostApi, operation: string, payload: unknown): () => unknown {
  if (operation === "canonical_json") {
    return () => host.canonicalJson(payload);
  }
  if (operation === "stable_hash") {
    return () => host.stableHash(payload);
  }
  if (!isRecord(payload)) {
    throw new Error("payload");
  }
  if (operation === "verify_audit_receipt") {
    return () => host.verifyAuditReceipt(payload.receipt, payload.key);
  }
  if (operation === "verify_controlled_integrity") {
    return () =>
      host.verifyControlledIntegrity(
        payload.value,
        payload.key,
        String(payload.keyId),
        payload.evidence,
      );
  }
  if (operation === "compare_authority_contracts") {
    return () => host.compareAuthorityContracts(payload.previous, payload.next);
  }
  throw new Error(`operation ${operation}`);
}

function normalize(operation: string, result: unknown): unknown {
  if (operation === "canonical_json" || operation === "stable_hash") {
    if (typeof result !== "string") {
      throw new Error("probe string");
    }
    return result;
  }
  if (operation === "verify_audit_receipt" || operation === "verify_controlled_integrity") {
    if (typeof result !== "boolean") {
      throw new Error("probe bool");
    }
    return result;
  }
  return compareView(result);
}

function timeLoop(
  warmup: number,
  iterations: number,
  call: () => unknown,
  operation: string,
): number[] {
  let sink = 0;
  for (let i = 0; i < warmup; i += 1) {
    sink ^= observe(operation, call());
  }
  const samples = new Array<number>(iterations);
  for (let i = 0; i < iterations; i += 1) {
    const started = process.hrtime.bigint();
    const result = call();
    sink ^= observe(operation, result);
    const finished = process.hrtime.bigint();
    const elapsed = Number(finished - started);
    if (!Number.isSafeInteger(elapsed) || elapsed < 0) {
      throw new Error("sample");
    }
    samples[i] = elapsed;
  }
  if (sink < 0) {
    throw new Error("observe");
  }
  return samples;
}

function observe(operation: string, result: unknown): number {
  if (operation === "canonical_json" || operation === "stable_hash") {
    if (typeof result !== "string") {
      throw new Error("observe string");
    }
    return result.length;
  }
  if (operation === "verify_audit_receipt" || operation === "verify_controlled_integrity") {
    if (typeof result !== "boolean") {
      throw new Error("observe bool");
    }
    return result ? 1 : 0;
  }
  return compareView(result).relationship.length;
}

function compareView(result: unknown): {
  relationship: string;
  widened: string[];
  narrowed: string[];
} {
  if (!isRecord(result) || typeof result.relationship !== "string") {
    throw new Error("observe compare");
  }
  if (!isStringArray(result.widened) || !isStringArray(result.narrowed)) {
    throw new Error("observe compare lists");
  }
  return {
    relationship: result.relationship,
    widened: [...result.widened],
    narrowed: [...result.narrowed],
  };
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function loadApi(selected: Role): Promise<HostApi> {
  if (selected === "typescript") {
    return import("../ts-baseline/index.ts");
  }
  const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
  const loaded = (await import(pathToFileURL(join(root, "bindings/node/index.js")).href)) as Record<
    string,
    unknown
  >;
  const api = typeof loaded.canonicalJson === "function" ? loaded : loaded.default;
  if (!isRecord(api) || typeof api.canonicalJson !== "function") {
    throw new Error("node addon exports");
  }
  return api as unknown as HostApi;
}
