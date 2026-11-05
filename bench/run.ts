import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { cpus, arch, release, type } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalJson,
  compareAuthorityContracts,
  resignAuditReceipt,
  signControlledIntegrity,
  stableHash,
  verifyAuditReceipt,
  verifyControlledIntegrity,
} from "./ts-baseline/index.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

declare const passedGateBrand: unique symbol;

type Mode = "full" | "smoke";

type PassedGate = {
  readonly [passedGateBrand]: true;
  readonly status: "passed";
  readonly canonicalize: 8;
  readonly hmac: 8;
  readonly compare: 7;
};

type HostImplementation = "typescript" | "node_napi" | "python_abi3";
type Implementation = HostImplementation | "rust_native";

type Operation =
  | "canonical_json"
  | "stable_hash"
  | "verify_audit_receipt"
  | "verify_controlled_integrity"
  | "compare_authority_contracts";

type VectorCaseName =
  | "canon-key-order-nested"
  | "hmac-audit-receipt-valid"
  | "hmac-controlled-sign-and-verify"
  | "cmp-v1-mixed-and-order";

type Shape = "object_tree" | "audit_receipt" | "controlled_value" | "authority_pair";

type CaseId =
  | { readonly source: "vector"; readonly name: VectorCaseName }
  | { readonly source: "synthetic"; readonly shape: Shape; readonly budget: number };

type Affinity =
  | { readonly status: "pinned"; readonly cpu: number }
  | { readonly status: "unpinned"; readonly reason: string };

type Environment = {
  readonly recordedAt: string;
  readonly gitSha: string;
  readonly gitDirty: boolean;
  readonly rustc: string;
  readonly cargoProfile: "release";
  readonly node: string;
  readonly python: string;
  readonly pythonModule: string;
  readonly nodeAddon: string;
  readonly rustBin: string;
  readonly os: string;
  readonly arch: string;
  readonly cpuModel: string;
  readonly affinity: Affinity;
  readonly runs: number;
  readonly isolate: "process";
  readonly gcInTimedRegion: false;
};

type HostSeries = {
  readonly implementation: HostImplementation;
  readonly operation: Operation;
  readonly caseId: CaseId;
  readonly inputDigest: string;
  readonly samplesNs: readonly number[];
};

type NativeSeries = {
  readonly implementation: "rust_native";
  readonly operation: Operation;
  readonly caseId: CaseId;
  readonly inputDigest: string;
  readonly samplesNs: readonly number[];
};

type Series = HostSeries | NativeSeries;

type Run = {
  readonly runIndex: number;
  readonly series: readonly Series[];
};

type Results = {
  readonly schema: 1;
  readonly mode: Mode;
  readonly environment: Environment;
  readonly vectorGate: PassedGate;
  readonly runs: readonly Run[];
};

type Stats = {
  readonly n: number;
  readonly minNs: number;
  readonly maxNs: number;
  readonly meanNs: number;
  readonly p50Ns: number;
  readonly p95Ns: number;
  readonly p99Ns: number;
};

type Spread = {
  readonly p50Ns: { readonly min: number; readonly max: number };
  readonly p95Ns: { readonly min: number; readonly max: number };
  readonly meanNs: { readonly min: number; readonly max: number };
};

type PreparedCase = {
  readonly operation: Operation;
  readonly caseId: CaseId;
  readonly warmup: number;
  readonly iterations: number;
  readonly payload: unknown;
};

type PlanMessage = {
  readonly schema: 1;
  readonly mode: Mode;
  readonly cases: readonly PreparedCase[];
};

type BuiltPlan = {
  readonly message: PlanMessage;
  readonly digests: readonly string[];
  readonly expected: readonly unknown[];
};

type ReplyMessage = {
  readonly probes: readonly { readonly operation: Operation; readonly caseId: CaseId; readonly observed: unknown }[];
  readonly samples: readonly { readonly operation: Operation; readonly caseId: CaseId; readonly ns: readonly number[] }[];
};

const OPERATIONS: readonly Operation[] = [
  "canonical_json",
  "stable_hash",
  "verify_audit_receipt",
  "verify_controlled_integrity",
  "compare_authority_contracts",
];

const HOSTS: readonly HostImplementation[] = ["typescript", "node_napi", "python_abi3"];
const IMPLEMENTATIONS: readonly Implementation[] = [...HOSTS, "rust_native"];
const FULL_RUNS = 5;
const SMOKE_RUNS = 1;
const BENCH_KEY = "bench-latency-key";
const CONTROLLED_KEY_ID = "bench-key";
const OBJECT_SEED = 0xa41c;
const GATE_LINES = [
  "ts-baseline canonicalize 8 ok",
  "ts-baseline hmac 8 ok",
  "ts-baseline compare 7 ok",
] as const;

const VECTOR_NAME: Record<Operation, VectorCaseName> = {
  canonical_json: "canon-key-order-nested",
  stable_hash: "canon-key-order-nested",
  verify_audit_receipt: "hmac-audit-receipt-valid",
  verify_controlled_integrity: "hmac-controlled-sign-and-verify",
  compare_authority_contracts: "cmp-v1-mixed-and-order",
};

const SYNTHETIC: Record<Operation, { readonly shape: Shape; readonly budgets: readonly number[] }> = {
  canonical_json: { shape: "object_tree", budgets: [8192, 65536, 524288] },
  stable_hash: { shape: "object_tree", budgets: [8192, 65536, 524288] },
  verify_audit_receipt: { shape: "audit_receipt", budgets: [8192, 65536] },
  verify_controlled_integrity: { shape: "controlled_value", budgets: [8192, 65536] },
  compare_authority_contracts: { shape: "authority_pair", budgets: [4096, 32768] },
};

const CLOCK = {
  typescript: "process.hrtime.bigint",
  node_napi: "process.hrtime.bigint",
  python_abi3: "time.perf_counter_ns",
  rust_native: "std::time::Instant",
} as const;

const VECTOR_NAMES: readonly VectorCaseName[] = [
  "canon-key-order-nested",
  "hmac-audit-receipt-valid",
  "hmac-controlled-sign-and-verify",
  "cmp-v1-mixed-and-order",
];

const SHAPES: readonly Shape[] = ["object_tree", "audit_receipt", "controlled_value", "authority_pair"];

interface VectorRow {
  readonly name: string;
  readonly input: unknown;
}

interface Tools {
  readonly python: string;
  readonly pythonVersion: string;
  readonly pythonModule: string;
  readonly nodeAddon: string;
  readonly rustBin: string;
  readonly rustc: string;
}

function family(operation: Operation): "canonicalize_and_hash" | "hmac_verify" | "compare" {
  if (operation === "canonical_json" || operation === "stable_hash") {
    return "canonicalize_and_hash";
  }
  if (operation === "verify_audit_receipt" || operation === "verify_controlled_integrity") {
    return "hmac_verify";
  }
  return "compare";
}

function effort(mode: Mode, caseId: CaseId): { warmup: number; iterations: number } {
  if (mode === "smoke") {
    return { warmup: 2, iterations: 5 };
  }
  const budget = caseId.source === "vector" ? 0 : caseId.budget;
  if (budget <= 8192) {
    return { warmup: 100, iterations: 2000 };
  }
  if (budget <= 65536) {
    return { warmup: 20, iterations: 400 };
  }
  return { warmup: 5, iterations: 80 };
}

function repeatsFor(mode: Mode): number {
  return mode === "full" ? FULL_RUNS : SMOKE_RUNS;
}

function orderedOperations(): Operation[] {
  const groups: Record<ReturnType<typeof family>, Operation[]> = {
    canonicalize_and_hash: [],
    hmac_verify: [],
    compare: [],
  };
  for (const operation of OPERATIONS) {
    groups[family(operation)].push(operation);
  }
  return [...groups.canonicalize_and_hash, ...groups.hmac_verify, ...groups.compare];
}

function plannedCases(mode: Mode): { operation: Operation; caseId: CaseId }[] {
  const planned: { operation: Operation; caseId: CaseId }[] = [];
  for (const operation of orderedOperations()) {
    planned.push({ operation, caseId: { source: "vector", name: VECTOR_NAME[operation] } });
    if (mode === "full") {
      const spec = SYNTHETIC[operation];
      for (const budget of spec.budgets) {
        planned.push({ operation, caseId: { source: "synthetic", shape: spec.shape, budget } });
      }
    }
  }
  return planned;
}

function caseLabel(caseId: CaseId): string {
  if (caseId.source === "vector") {
    return `vector:${caseId.name}`;
  }
  return `synthetic:${caseId.shape}:${caseId.budget}`;
}

function runVectorGate(): PassedGate {
  const child = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "--disable-warning=ExperimentalWarning",
      join(root, "bench/ts-baseline/gate.ts"),
    ],
    { encoding: "utf8" },
  );
  const stdout = child.stdout ?? "";
  if (child.status !== 0) {
    process.stderr.write(stdout);
    process.stderr.write(child.stderr ?? "");
    throw new Error("vector gate failed");
  }
  const lines = new Set(
    stdout
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0),
  );
  for (const line of GATE_LINES) {
    if (!lines.has(line)) {
      throw new Error(`vector gate missing ${line}`);
    }
  }
  return passedGate();
}

function passedGate(): PassedGate {
  return { status: "passed", canonicalize: 8, hmac: 8, compare: 7 } as PassedGate;
}

function planFor(mode: Mode, rows: readonly VectorRow[]): BuiltPlan {
  const trees = new Map<number, unknown>();
  const audits = new Map<number, { receipt: unknown; key: string }>();
  const controlled = new Map<number, ControlledPayload>();
  const compares = new Map<number, { previous: unknown; next: unknown }>();
  const cases: PreparedCase[] = [];
  const digests: string[] = [];
  const expected: unknown[] = [];
  for (const planned of plannedCases(mode)) {
    const timing = effort(mode, planned.caseId);
    const payload = payloadFor(planned.operation, planned.caseId, rows, trees, audits, controlled, compares);
    cases.push({
      operation: planned.operation,
      caseId: planned.caseId,
      warmup: timing.warmup,
      iterations: timing.iterations,
      payload,
    });
    digests.push(digestFor(planned.operation, payload));
    expected.push(expectedObserved(planned.operation, payload));
  }
  return { message: { schema: 1, mode, cases }, digests, expected };
}

interface ControlledPayload {
  readonly value: unknown;
  readonly key: string;
  readonly keyId: string;
  readonly evidence: unknown;
}

function payloadFor(
  operation: Operation,
  caseId: CaseId,
  rows: readonly VectorRow[],
  trees: Map<number, unknown>,
  audits: Map<number, { receipt: unknown; key: string }>,
  controlled: Map<number, ControlledPayload>,
  compares: Map<number, { previous: unknown; next: unknown }>,
): unknown {
  if (caseId.source === "vector") {
    return vectorPayload(operation, rows);
  }
  if (caseId.shape === "object_tree") {
    const cached = trees.get(caseId.budget);
    if (cached !== undefined) {
      return cached;
    }
    const built = objectTree(caseId.budget);
    trees.set(caseId.budget, built);
    return built;
  }
  if (caseId.shape === "audit_receipt") {
    const cached = audits.get(caseId.budget);
    if (cached !== undefined) {
      return cached;
    }
    const built = auditReceipt(rows, caseId.budget);
    audits.set(caseId.budget, built);
    return built;
  }
  if (caseId.shape === "controlled_value") {
    const cached = controlled.get(caseId.budget);
    if (cached !== undefined) {
      return cached;
    }
    const built = controlledValue(caseId.budget);
    controlled.set(caseId.budget, built);
    return built;
  }
  const cached = compares.get(caseId.budget);
  if (cached !== undefined) {
    return cached;
  }
  const built = authorityPair(caseId.budget);
  compares.set(caseId.budget, built);
  return built;
}

function vectorPayload(operation: Operation, rows: readonly VectorRow[]): unknown {
  const row = rowNamed(rows, VECTOR_NAME[operation]);
  if (!isRecord(row.input)) {
    throw new Error(`${row.name} input`);
  }
  const input = row.input;
  if (operation === "canonical_json" || operation === "stable_hash") {
    return input;
  }
  if (operation === "verify_audit_receipt") {
    return { receipt: input.receipt, key: input.signingKeyUtf8 };
  }
  if (operation === "verify_controlled_integrity") {
    if (!isRecord(input.verifyCases)) {
      throw new Error("verifyCases");
    }
    return {
      value: input.value,
      key: input.signingKeyUtf8,
      keyId: input.keyId,
      evidence: input.verifyCases.valid,
    };
  }
  return { previous: input.previous, next: input.next };
}

function objectTree(budget: number): unknown {
  const rng = mulberry32(OBJECT_SEED);
  const root: Record<string, unknown> = {
    "2": "two",
    "10": "ten",
    nest: nest(4),
    mix: [seededString(rng, 4), 1, null],
  };
  let guard = 0;
  while (utf8Length(canonicalJson(root)) < budget) {
    const deficit = budget - utf8Length(canonicalJson(root));
    const count = deficit > 256 ? Math.min(400, Math.max(1, Math.floor(deficit / 40))) : 1;
    const width = deficit > 256 ? 8 : deficit + 8;
    for (let index = 0; index < count; index += 1) {
      root[`f${Object.keys(root).length.toString(36)}`] = seededString(rng, width);
    }
    guard += 1;
    if (guard > 80) {
      throw new Error(`object tree ${budget} did not reach size`);
    }
  }
  return root;
}

function nest(level: number): Record<string, unknown> {
  if (level === 0) {
    return { "2": "leaf", "10": "leaf" };
  }
  return { "2": level, "10": level, down: nest(level - 1) };
}

function auditReceipt(rows: readonly VectorRow[], budget: number): { receipt: unknown; key: string } {
  const source = rowNamed(rows, "hmac-audit-receipt-valid");
  if (!isRecord(source.input) || !isRecord(source.input.receipt)) {
    throw new Error("audit vector");
  }
  const receipt = structuredClone(source.input.receipt);
  if (!isRecord(receipt) || !isRecord(receipt.artifacts)) {
    throw new Error("audit artifacts");
  }
  const artifacts = receipt.artifacts;
  let signed: unknown = resignAuditReceipt(receipt, BENCH_KEY);
  let index = 0;
  let guard = 0;
  while (utf8Length(canonicalJson(signed)) < budget) {
    const deficit = budget - utf8Length(canonicalJson(signed));
    const batch = Math.max(1, Math.min(80, Math.floor(deficit / 180)));
    for (let step = 0; step < batch; step += 1) {
      const value = { pad: "q".repeat(48), n: index };
      artifacts[`benchPad${index}`] = { hash: stableHash(value), value };
      index += 1;
    }
    signed = resignAuditReceipt(receipt, BENCH_KEY);
    guard += 1;
    if (guard > 100) {
      throw new Error(`audit receipt ${budget} did not reach size`);
    }
  }
  if (!verifyAuditReceipt(signed, BENCH_KEY)) {
    throw new Error("synthetic audit receipt does not verify");
  }
  return { receipt: signed, key: BENCH_KEY };
}

function controlledValue(budget: number): ControlledPayload {
  const value: Record<string, unknown> = { "2": "two", "10": "ten", parts: [] as string[] };
  const parts = value.parts as string[];
  let guard = 0;
  while (utf8Length(canonicalJson(value)) < budget) {
    const deficit = budget - utf8Length(canonicalJson(value));
    const batch = Math.max(1, Math.min(100, Math.floor(deficit / 60)));
    for (let step = 0; step < batch; step += 1) {
      parts.push("q".repeat(48));
    }
    guard += 1;
    if (guard > 100) {
      throw new Error(`controlled value ${budget} did not reach size`);
    }
  }
  const evidence = signControlledIntegrity(value, BENCH_KEY, CONTROLLED_KEY_ID);
  if (!verifyControlledIntegrity(value, BENCH_KEY, CONTROLLED_KEY_ID, evidence)) {
    throw new Error("synthetic controlled value does not verify");
  }
  return { value, key: BENCH_KEY, keyId: CONTROLLED_KEY_ID, evidence };
}

function authorityPair(budget: number): { previous: unknown; next: unknown } {
  const ids: string[] = ["alpha"];
  const previous = {
    version: "2",
    filesystem: { read: ids },
    network: { https: [httpsRule("alpha.example.com", 443)] },
    git: { hooks: ["hook"] },
  };
  const next = {
    version: "2",
    filesystem: { read: ids },
    network: { https: [httpsRule("beta.example.com", 8443)] },
    git: { hooks: [] as string[] },
  };
  let guard = 0;
  while (compareBytes(previous, next) < budget) {
    const deficit = budget - compareBytes(previous, next);
    const batch = Math.max(1, Math.min(200, Math.floor(deficit / 24)));
    for (let step = 0; step < batch; step += 1) {
      ids.push(`id${ids.length.toString(36)}`);
    }
    guard += 1;
    if (guard > 100) {
      throw new Error(`authority pair ${budget} did not reach size`);
    }
  }
  const result = compareAuthorityContracts(previous, next);
  if (result.relationship !== "mixed" || result.widened.length === 0 || result.narrowed.length === 0) {
    throw new Error(`synthetic compare is ${result.relationship}`);
  }
  return { previous, next };
}

function httpsRule(host: string, port: number): Record<string, unknown> {
  return {
    protocol: "https",
    host,
    port,
    methods: ["GET"],
    resolution: "public-only",
    redirects: "none",
    maxResponseBytes: 1024,
    timeoutMs: 1000,
  };
}

function digestFor(operation: Operation, payload: unknown): string {
  if (operation === "compare_authority_contracts") {
    const pair = pairOf(payload);
    return sha256(`${canonicalJson(pair.previous)}\n${canonicalJson(pair.next)}`);
  }
  if (operation === "verify_audit_receipt") {
    if (!isRecord(payload)) {
      throw new Error("audit digest");
    }
    return sha256(canonicalJson(payload.receipt));
  }
  if (operation === "verify_controlled_integrity") {
    if (!isRecord(payload)) {
      throw new Error("controlled digest");
    }
    return sha256(canonicalJson(payload.value));
  }
  return sha256(canonicalJson(payload));
}

function expectedObserved(operation: Operation, payload: unknown): unknown {
  if (operation === "canonical_json") {
    return canonicalJson(payload);
  }
  if (operation === "stable_hash") {
    return stableHash(payload);
  }
  if (operation === "verify_audit_receipt") {
    if (!isRecord(payload)) {
      throw new Error("audit payload");
    }
    if (!verifyAuditReceipt(payload.receipt, payload.key)) {
      throw new Error("audit fixture does not verify");
    }
    return true;
  }
  if (operation === "verify_controlled_integrity") {
    if (!isRecord(payload) || typeof payload.keyId !== "string") {
      throw new Error("controlled payload");
    }
    if (!verifyControlledIntegrity(payload.value, payload.key, payload.keyId, payload.evidence)) {
      throw new Error("controlled fixture does not verify");
    }
    return true;
  }
  const pair = pairOf(payload);
  const result = compareAuthorityContracts(pair.previous, pair.next);
  return {
    relationship: result.relationship,
    widened: [...result.widened],
    narrowed: [...result.narrowed],
  };
}

function finish(mode: Mode, environment: Environment, gate: PassedGate, runs: readonly Run[]): Results {
  if (gate.canonicalize !== 8 || gate.hmac !== 8 || gate.compare !== 7 || gate.status !== "passed") {
    throw new Error("gate");
  }
  return { schema: 1, mode, environment, vectorGate: gate, runs };
}

function percentile(sortedAsc: readonly number[], p: number): number {
  const count = sortedAsc.length;
  if (count === 0) {
    throw new Error("empty samples");
  }
  const index = Math.min(count - 1, Math.max(0, Math.ceil(p * count) - 1));
  const value = sortedAsc[index];
  if (value === undefined) {
    throw new Error("percentile");
  }
  return value;
}

function stats(samplesNs: readonly number[]): Stats {
  if (samplesNs.length === 0) {
    throw new Error("empty samples");
  }
  const sorted = [...samplesNs].sort((left, right) => left - right);
  let sum = 0;
  for (const sample of samplesNs) {
    sum += sample;
  }
  const minNs = sorted[0];
  const maxNs = sorted[sorted.length - 1];
  if (minNs === undefined || maxNs === undefined) {
    throw new Error("stats");
  }
  return {
    n: samplesNs.length,
    minNs,
    maxNs,
    meanNs: sum / samplesNs.length,
    p50Ns: percentile(sorted, 0.5),
    p95Ns: percentile(sorted, 0.95),
    p99Ns: percentile(sorted, 0.99),
  };
}

function spread(runs: readonly Run[], implementation: Implementation, operation: Operation, caseId: CaseId): Spread {
  const perRun = runs.map((run) => {
    const series = run.series.find(
      (item) => item.implementation === implementation && item.operation === operation && sameCase(item.caseId, caseId),
    );
    if (!series) {
      throw new Error(`missing ${implementation} ${operation} ${caseLabel(caseId)}`);
    }
    return stats(series.samplesNs);
  });
  return {
    p50Ns: minMax(perRun.map((item) => item.p50Ns)),
    p95Ns: minMax(perRun.map((item) => item.p95Ns)),
    meanNs: minMax(perRun.map((item) => item.meanNs)),
  };
}

function rankHosts(series: readonly HostSeries[]): readonly HostSeries[] {
  return [...series].sort(
    (left, right) => HOSTS.indexOf(left.implementation) - HOSTS.indexOf(right.implementation),
  );
}

function readResults(bytes: Uint8Array): Results {
  const parsed: unknown = JSON.parse(Buffer.from(bytes).toString("utf8"));
  const rootRecord = needRecord(parsed, "results");
  exactKeys(rootRecord, ["schema", "mode", "environment", "vectorGate", "runs"]);
  if (rootRecord.schema !== 1) {
    throw new Error("schema");
  }
  const mode = needMode(rootRecord.mode);
  const environment = needEnvironment(rootRecord.environment, mode);
  const vectorGate = needGate(rootRecord.vectorGate);
  if (!Array.isArray(rootRecord.runs)) {
    throw new Error("runs");
  }
  const planned = plannedCases(mode);
  const runs = rootRecord.runs.map((run, index) => needRun(run, index, mode, planned));
  if (runs.length !== environment.runs) {
    throw new Error("run count");
  }
  const results = finish(mode, environment, vectorGate, runs);
  for (const run of results.runs) {
    for (const series of run.series) {
      assertDerived(series.samplesNs);
    }
  }
  return results;
}

function writeResultsAtomic(results: Results, path: string): void {
  const text = `${JSON.stringify(results)}\n`;
  readResults(Buffer.from(text));
  mkdirSync(dirname(path), { recursive: true });
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.tmp`);
  writeFileSync(temporary, text);
  renameSync(temporary, path);
}

async function collect(gate: PassedGate, built: BuiltPlan, tools: Tools): Promise<Run[]> {
  if (gate.status !== "passed") {
    throw new Error("gate");
  }
  const repeats = repeatsFor(built.message.mode);
  const timeoutMs = built.message.mode === "full" ? 30 * 60 * 1000 : 60 * 1000;
  const runs: Run[] = [];
  for (let runIndex = 0; runIndex < repeats; runIndex += 1) {
    const series: Series[] = [];
    for (const implementation of IMPLEMENTATIONS) {
      process.stderr.write(
        `bench ${built.message.mode} run ${runIndex + 1}/${repeats} ${implementation}\n`,
      );
      const reply = await spawnRunner(implementation, built.message, tools, timeoutMs);
      series.push(...acceptReply(implementation, built, reply));
    }
    runs.push({ runIndex, series });
  }
  return runs;
}

function acceptReply(implementation: Implementation, built: BuiltPlan, reply: ReplyMessage): Series[] {
  if (reply.probes.length !== built.message.cases.length || reply.samples.length !== built.message.cases.length) {
    throw new Error(`${implementation} reply length`);
  }
  const series: Series[] = [];
  for (let index = 0; index < built.message.cases.length; index += 1) {
    const planned = built.message.cases[index];
    const probe = reply.probes[index];
    const sample = reply.samples[index];
    if (!planned || !probe || !sample) {
      throw new Error(`${implementation} reply`);
    }
    if (probe.operation !== planned.operation || sample.operation !== planned.operation) {
      throw new Error(`${implementation} operation`);
    }
    if (!sameCase(probe.caseId, planned.caseId) || !sameCase(sample.caseId, planned.caseId)) {
      throw new Error(`${implementation} case`);
    }
    const expected = built.expected[index];
    if (!sameObserved(planned.operation, expected, probe.observed)) {
      throw new Error(
        `${implementation} probe ${planned.operation} ${caseLabel(planned.caseId)} expected ${snippet(expected)} observed ${snippet(probe.observed)}`,
      );
    }
    if (sample.ns.length !== planned.iterations) {
      throw new Error(`${implementation} sample count ${sample.ns.length}`);
    }
    const digest = built.digests[index];
    if (digest === undefined || !/^[0-9a-f]{64}$/.test(digest)) {
      throw new Error("digest");
    }
    series.push(asSeries(implementation, planned.operation, planned.caseId, digest, sample.ns));
  }
  return series;
}

function asSeries(
  implementation: Implementation,
  operation: Operation,
  caseId: CaseId,
  inputDigest: string,
  samplesNs: readonly number[],
): Series {
  if (implementation === "rust_native") {
    return { implementation, operation, caseId, inputDigest, samplesNs };
  }
  return { implementation, operation, caseId, inputDigest, samplesNs };
}

function printReport(results: Results): void {
  const grouped = groupSeries(results);
  const warnings: string[] = [];
  const hostRows: string[][] = [];
  const nativeRows: string[][] = [];
  const clock = IMPLEMENTATIONS.map((name) => `${name} ${CLOCK[name]}`).join("  ");
  console.log(`host-inclusive  marshalling included  runs ${results.environment.runs}`);
  console.log(`clock  ${clock}`);
  for (const operation of orderedOperations()) {
    for (const planned of plannedCases(results.mode)) {
      if (planned.operation !== operation) {
        continue;
      }
      const rowSeries: HostSeries[] = [];
      for (const implementation of HOSTS) {
        const group = grouped.get(seriesKey(implementation, operation, planned.caseId)) ?? [];
        const chosen = representative(group);
        if (chosen.implementation === "rust_native") {
          throw new Error("native in host table");
        }
        rowSeries.push(chosen);
        const warning = unstableLine(group, `${operation} ${caseLabel(planned.caseId)} ${implementation}`);
        if (warning) {
          warnings.push(warning);
        }
      }
      for (const series of rankHosts(rowSeries)) {
        hostRows.push(measureCells(series, results.runs));
      }
      const nativeGroup = grouped.get(seriesKey("rust_native", operation, planned.caseId)) ?? [];
      const native = representative(nativeGroup);
      const nativeCells = measureCells(native, results.runs);
      nativeCells.splice(2, 1);
      nativeRows.push(nativeCells);
      const nativeWarning = unstableLine(nativeGroup, `${operation} ${caseLabel(planned.caseId)} rust_native`);
      if (nativeWarning) {
        warnings.push(nativeWarning);
      }
    }
  }
  printTable(
    ["operation", "case", "impl", "p50 us", "p95 us", "p99 us", "mean us", "n", "p95 spread us"],
    hostRows,
  );
  console.log("");
  console.log("rust-native reference  owned Json  walk excluded  not ranked with the hosts");
  printTable(["operation", "case", "p50 us", "p95 us", "p99 us", "mean us", "n", "p95 spread us"], nativeRows);
  for (const warning of warnings) {
    console.log(warning);
  }
  for (const line of GATE_LINES) {
    console.log(line);
  }
  console.log(`bench ${results.mode} ok`);
}

async function main(argv: readonly string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args.command === "parse") {
    readResults(readFileSync(args.file));
    console.log("parse ok");
    return 0;
  }
  const nodeMajor = Number(process.versions.node.split(".")[0]);
  if (nodeMajor !== 22) {
    throw new Error(`node ${process.version} is not 22`);
  }
  const affinity = resolveAffinity(args.command, args.allowUnpinned);
  const gate = runVectorGate();
  const tools = prepareTools(args.python);
  const rows = loadRows();
  const built = planFor(args.command, rows);
  const runs = await collect(gate, built, tools);
  const git = gitMeta();
  const environment: Environment = {
    recordedAt: new Date().toISOString(),
    gitSha: git.sha,
    gitDirty: git.dirty,
    rustc: tools.rustc,
    cargoProfile: "release",
    node: process.version,
    python: tools.pythonVersion,
    pythonModule: tools.pythonModule,
    nodeAddon: tools.nodeAddon,
    rustBin: tools.rustBin,
    os: `${type()} ${release()}`,
    arch: arch(),
    cpuModel: cpuModel(),
    affinity,
    runs: repeatsFor(args.command),
    isolate: "process",
    gcInTimedRegion: false,
  };
  const results = finish(args.command, environment, gate, runs);
  const path = outputPath(args.command, args.out, git.dirty);
  writeResultsAtomic(results, path);
  process.stderr.write(`wrote ${path}\n`);
  printReport(results);
  return 0;
}

function outputPath(mode: Mode, out: string | undefined, dirty: boolean): string {
  if (out) {
    return out;
  }
  if (mode === "smoke") {
    throw new Error("smoke requires --out");
  }
  if (dirty) {
    return join(root, "bench/results/full.dirty.json");
  }
  return join(root, "bench/results/full.json");
}

function resolveAffinity(mode: Mode, allowUnpinned: boolean): Affinity {
  if (mode === "smoke") {
    return { status: "unpinned", reason: "smoke does not pin" };
  }
  const already = process.env.BENCH_AFFINITY_PINNED === "1";
  const allowed = readAllowedCpus();
  if (already) {
    if (allowed.length === 1 && allowed[0] !== undefined) {
      return { status: "pinned", cpu: allowed[0] };
    }
    return { status: "unpinned", reason: "taskset returned a mask wider than one cpu" };
  }
  if (allowUnpinned) {
    return { status: "unpinned", reason: "allow-unpinned" };
  }
  if (allowed.length === 1 && allowed[0] !== undefined) {
    return { status: "pinned", cpu: allowed[0] };
  }
  const taskset = findTaskset();
  if (!taskset) {
    return { status: "unpinned", reason: "taskset not found" };
  }
  if (allowed.length === 0) {
    return { status: "unpinned", reason: "cpu mask unavailable" };
  }
  const lowest = Math.min(...allowed);
  const child = spawnSync(
    taskset,
    ["-c", String(lowest), process.execPath, ...process.execArgv, ...process.argv.slice(1)],
    { env: { ...process.env, BENCH_AFFINITY_PINNED: "1" }, stdio: "inherit" },
  );
  process.exit(child.status ?? 1);
}

function prepareTools(python: string): Tools {
  const info = pythonInfo(python);
  const addonPath = join(root, "bindings/node/index.js");
  let nodeAddon: string;
  try {
    nodeAddon = realpathSync(addonPath);
  } catch {
    throw new Error("bindings/node/index.js is missing. Build the release addon before timing.");
  }
  const rustc = commandText("rustc", ["--version"]);
  const rustBin = buildRustBin();
  return {
    python,
    pythonVersion: info.version,
    pythonModule: info.moduleFile,
    nodeAddon,
    rustBin,
    rustc,
  };
}

function buildRustBin(): string {
  const manifest = join(root, "bench/rust-native/Cargo.toml");
  const target = join(root, "target");
  const child = spawnSync("cargo", ["build", "--release", "--manifest-path", manifest], {
    env: { ...process.env, CARGO_TARGET_DIR: target },
    encoding: "utf8",
  });
  if (child.status !== 0) {
    process.stderr.write(child.stdout ?? "");
    process.stderr.write(child.stderr ?? "");
    throw new Error("rust-native release build failed");
  }
  const bin = join(target, "release", "agent-receipts-bench-native");
  return realpathSync(bin);
}

function pythonInfo(python: string): { version: string; moduleFile: string } {
  const script = [
    "import agent_receipts, sys",
    "print(sys.version.replace('\\n', ' '))",
    "print(agent_receipts.__file__)",
  ].join("\n");
  const child = spawnSync(python, ["-c", script], { encoding: "utf8" });
  if (child.status !== 0) {
    throw new Error(`python cannot import agent_receipts\n${child.stderr ?? ""}`);
  }
  const lines = child.stdout.trim().split("\n");
  const moduleFile = lines[lines.length - 1] ?? "";
  const version = lines.slice(0, -1).join(" ").trim();
  if (!moduleFile.includes("site-packages")) {
    throw new Error(`python module is not an installed wheel: ${moduleFile}`);
  }
  return { version, moduleFile };
}

function spawnRunner(
  implementation: Implementation,
  plan: PlanMessage,
  tools: Tools,
  timeoutMs: number,
): Promise<ReplyMessage> {
  const input = JSON.stringify(messageForRunner(plan));
  let command = tools.rustBin;
  let args: string[] = [];
  if (implementation === "typescript" || implementation === "node_napi") {
    command = process.execPath;
    args = [
      "--experimental-strip-types",
      "--disable-warning=ExperimentalWarning",
      join(root, "bench/runners/node-host.ts"),
      implementation,
    ];
  } else if (implementation === "python_abi3") {
    command = tools.python;
    args = [join(root, "bench/runners/python_runner.py")];
  }
  return runChild(command, args, input, timeoutMs, implementation).then(({ stdout }) => parseReply(stdout, implementation));
}

function messageForRunner(plan: PlanMessage): PlanMessage {
  return {
    schema: 1,
    mode: plan.mode,
    cases: plan.cases.map((item) => ({
      operation: item.operation,
      caseId: item.caseId,
      warmup: item.warmup,
      iterations: item.iterations,
      payload: item.payload,
    })),
  };
}

function runChild(
  command: string,
  args: readonly string[],
  input: string,
  timeoutMs: number,
  label: string,
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      out.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      err.push(chunk);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(out).toString("utf8");
      const stderr = Buffer.concat(err).toString("utf8");
      if (code !== 0) {
        reject(new Error(`${label} exit ${code}\n${stderr.slice(-2000)}\n${stdout.slice(0, 400)}`));
        return;
      }
      resolve({ stdout, stderr });
    });
    child.stdin.end(input);
  });
}

function parseReply(stdout: string, implementation: Implementation): ReplyMessage {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error(`${implementation} reply is not json`);
  }
  const record = needRecord(parsed, "reply");
  exactKeys(record, ["schema", "probes", "samples"]);
  if (record.schema !== 1 || !Array.isArray(record.probes) || !Array.isArray(record.samples)) {
    throw new Error(`${implementation} reply schema`);
  }
  const probes = record.probes.map((probe) => {
    const item = needRecord(probe, "probe");
    exactKeys(item, ["operation", "caseId", "observed"]);
    return {
      operation: needOperation(item.operation),
      caseId: parseCaseId(item.caseId),
      observed: item.observed,
    };
  });
  const samples = record.samples.map((sample) => {
    const item = needRecord(sample, "sample");
    exactKeys(item, ["operation", "caseId", "ns"]);
    if (!Array.isArray(item.ns)) {
      throw new Error("samples");
    }
    const ns = item.ns.map((value) => {
      if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error("sample is not an integer nanosecond");
      }
      return value;
    });
    return { operation: needOperation(item.operation), caseId: parseCaseId(item.caseId), ns };
  });
  return { probes, samples };
}

function measureCells(series: Series, runs: readonly Run[]): string[] {
  const derived = stats(representative(groupOf(runs, series)).samplesNs);
  const width = spread(runs, series.implementation, series.operation, series.caseId);
  return [
    series.operation,
    caseLabel(series.caseId),
    series.implementation,
    us(derived.p50Ns),
    us(derived.p95Ns),
    us(derived.p99Ns),
    us(derived.meanNs),
    String(derived.n),
    us(width.p95Ns.max - width.p95Ns.min),
  ];
}

function printTable(header: readonly string[], rows: readonly (readonly string[])[]): void {
  const widths = header.map((cell, index) => {
    let width = cell.length;
    for (const row of rows) {
      width = Math.max(width, row[index]?.length ?? 0);
    }
    return width;
  });
  const format = (cells: readonly string[]) =>
    cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  console.log(format(header));
  for (const row of rows) {
    console.log(format(row));
  }
}

function groupSeries(results: Results): Map<string, Series[]> {
  const grouped = new Map<string, Series[]>();
  for (const run of results.runs) {
    for (const series of run.series) {
      const key = seriesKey(series.implementation, series.operation, series.caseId);
      const list = grouped.get(key);
      if (list) {
        list.push(series);
      } else {
        grouped.set(key, [series]);
      }
    }
  }
  return grouped;
}

function groupOf(runs: readonly Run[], series: Series): Series[] {
  const found: Series[] = [];
  for (const run of runs) {
    for (const item of run.series) {
      if (
        item.implementation === series.implementation &&
        item.operation === series.operation &&
        sameCase(item.caseId, series.caseId)
      ) {
        found.push(item);
      }
    }
  }
  return found;
}

function representative(group: readonly Series[]): Series {
  if (group.length === 0) {
    throw new Error("empty group");
  }
  const ranked = [...group].sort((left, right) => stats(left.samplesNs).p50Ns - stats(right.samplesNs).p50Ns);
  const chosen = ranked[Math.floor((ranked.length - 1) / 2)];
  if (!chosen) {
    throw new Error("representative");
  }
  return chosen;
}

function unstableLine(group: readonly Series[], label: string): string | undefined {
  if (group.length === 0) {
    return undefined;
  }
  const perRun = group.map((series) => stats(series.samplesNs));
  const count = perRun[0]?.n ?? 0;
  if (count < 400) {
    return undefined;
  }
  const p95s = perRun.map((item) => item.p95Ns).sort((left, right) => left - right);
  const mid = percentile(p95s, 0.5);
  const width = (p95s[p95s.length - 1] ?? 0) - (p95s[0] ?? 0);
  if (width > 0.15 * mid) {
    return `unstable ${label}`;
  }
  return undefined;
}

function seriesKey(implementation: Implementation, operation: Operation, caseId: CaseId): string {
  return `${implementation}\u0000${operation}\u0000${caseLabel(caseId)}`;
}

function us(ns: number): string {
  return (ns / 1000).toFixed(2);
}

function assertDerived(samplesNs: readonly number[]): void {
  const derived = stats(samplesNs);
  if (derived.n !== samplesNs.length) {
    throw new Error("n");
  }
  if (
    derived.minNs > derived.p50Ns ||
    derived.p50Ns > derived.p95Ns ||
    derived.p95Ns > derived.p99Ns ||
    derived.p99Ns > derived.maxNs
  ) {
    throw new Error("percentile order");
  }
  if (derived.meanNs < derived.minNs || derived.meanNs > derived.maxNs) {
    throw new Error("mean");
  }
}

function needRun(
  value: unknown,
  index: number,
  mode: Mode,
  planned: readonly { operation: Operation; caseId: CaseId }[],
): Run {
  const record = needRecord(value, "run");
  exactKeys(record, ["runIndex", "series"]);
  if (record.runIndex !== index) {
    throw new Error("runIndex");
  }
  if (!Array.isArray(record.series)) {
    throw new Error("series");
  }
  const expectedCount = planned.length * IMPLEMENTATIONS.length;
  if (record.series.length !== expectedCount) {
    throw new Error("series count");
  }
  const series = record.series.map((item, seriesIndex) => {
    const implementation = IMPLEMENTATIONS[Math.floor(seriesIndex / planned.length)];
    const operation = planned[seriesIndex % planned.length];
    if (!operation || !implementation) {
      throw new Error("series index");
    }
    return needSeries(item, implementation, operation.operation, operation.caseId, mode);
  });
  return { runIndex: index, series };
}

function needSeries(
  value: unknown,
  implementation: Implementation,
  operation: Operation,
  caseId: CaseId,
  mode: Mode,
): Series {
  const record = needRecord(value, "series");
  exactKeys(record, ["implementation", "operation", "caseId", "inputDigest", "samplesNs"]);
  if (record.implementation !== implementation || needOperation(record.operation) !== operation) {
    throw new Error("series key");
  }
  const parsedCase = parseCaseId(record.caseId);
  if (!sameCase(parsedCase, caseId)) {
    throw new Error("series case");
  }
  if (typeof record.inputDigest !== "string" || !/^[0-9a-f]{64}$/.test(record.inputDigest)) {
    throw new Error("inputDigest");
  }
  if (!Array.isArray(record.samplesNs)) {
    throw new Error("samplesNs");
  }
  const samplesNs = record.samplesNs.map((sample) => {
    if (typeof sample !== "number" || !Number.isSafeInteger(sample) || sample < 0) {
      throw new Error("sample is not an integer nanosecond");
    }
    return sample;
  });
  const timing = effort(mode, caseId);
  if (samplesNs.length !== timing.iterations) {
    throw new Error(`sample length ${samplesNs.length}`);
  }
  return asSeries(implementation, operation, parsedCase, record.inputDigest, samplesNs);
}

function needEnvironment(value: unknown, mode: Mode): Environment {
  const record = needRecord(value, "environment");
  exactKeys(record, [
    "recordedAt",
    "gitSha",
    "gitDirty",
    "rustc",
    "cargoProfile",
    "node",
    "python",
    "pythonModule",
    "nodeAddon",
    "rustBin",
    "os",
    "arch",
    "cpuModel",
    "affinity",
    "runs",
    "isolate",
    "gcInTimedRegion",
  ]);
  if (typeof record.recordedAt !== "string" || record.recordedAt.length === 0) {
    throw new Error("recordedAt");
  }
  if (typeof record.gitSha !== "string" || !/^[0-9a-f]{40}$/.test(record.gitSha)) {
    throw new Error("gitSha");
  }
  if (typeof record.gitDirty !== "boolean") {
    throw new Error("gitDirty");
  }
  for (const key of ["rustc", "node", "python", "pythonModule", "nodeAddon", "rustBin", "os", "arch", "cpuModel"]) {
    if (typeof record[key] !== "string" || record[key].length === 0) {
      throw new Error(key);
    }
  }
  if (!String(record.pythonModule).includes("site-packages")) {
    throw new Error("pythonModule");
  }
  if (record.cargoProfile !== "release" || record.isolate !== "process" || record.gcInTimedRegion !== false) {
    throw new Error("environment literal");
  }
  if (record.runs !== repeatsFor(mode)) {
    throw new Error("environment.runs");
  }
  return {
    recordedAt: record.recordedAt,
    gitSha: record.gitSha,
    gitDirty: record.gitDirty,
    rustc: String(record.rustc),
    cargoProfile: "release",
    node: String(record.node),
    python: String(record.python),
    pythonModule: String(record.pythonModule),
    nodeAddon: String(record.nodeAddon),
    rustBin: String(record.rustBin),
    os: String(record.os),
    arch: String(record.arch),
    cpuModel: String(record.cpuModel),
    affinity: needAffinity(record.affinity),
    runs: record.runs,
    isolate: "process",
    gcInTimedRegion: false,
  };
}

function needAffinity(value: unknown): Affinity {
  const record = needRecord(value, "affinity");
  if (record.status === "pinned") {
    exactKeys(record, ["status", "cpu"]);
    if (typeof record.cpu !== "number" || !Number.isSafeInteger(record.cpu) || record.cpu < 0) {
      throw new Error("cpu");
    }
    return { status: "pinned", cpu: record.cpu };
  }
  if (record.status === "unpinned") {
    exactKeys(record, ["status", "reason"]);
    if (typeof record.reason !== "string" || record.reason.length === 0) {
      throw new Error("affinity reason");
    }
    return { status: "unpinned", reason: record.reason };
  }
  throw new Error("affinity");
}

function needGate(value: unknown): PassedGate {
  const record = needRecord(value, "vectorGate");
  exactKeys(record, ["status", "canonicalize", "hmac", "compare"]);
  if (record.status !== "passed" || record.canonicalize !== 8 || record.hmac !== 8 || record.compare !== 7) {
    throw new Error("vectorGate");
  }
  return passedGate();
}

function parseCaseId(value: unknown): CaseId {
  const record = needRecord(value, "caseId");
  if (record.source === "vector") {
    exactKeys(record, ["source", "name"]);
    if (!isVectorName(record.name)) {
      throw new Error("vector case");
    }
    return { source: "vector", name: record.name };
  }
  if (record.source === "synthetic") {
    exactKeys(record, ["source", "shape", "budget"]);
    if (!isShape(record.shape) || typeof record.budget !== "number" || !Number.isSafeInteger(record.budget)) {
      throw new Error("synthetic case");
    }
    return { source: "synthetic", shape: record.shape, budget: record.budget };
  }
  throw new Error("caseId");
}

function needMode(value: unknown): Mode {
  if (value === "full" || value === "smoke") {
    return value;
  }
  throw new Error("mode");
}

function needOperation(value: unknown): Operation {
  if (
    value === "canonical_json" ||
    value === "stable_hash" ||
    value === "verify_audit_receipt" ||
    value === "verify_controlled_integrity" ||
    value === "compare_authority_contracts"
  ) {
    return value;
  }
  throw new Error("operation");
}

function sameCase(left: CaseId, right: CaseId): boolean {
  return caseLabel(left) === caseLabel(right);
}

function sameObserved(operation: Operation, expected: unknown, observed: unknown): boolean {
  return JSON.stringify(normalizeObserved(operation, expected)) === JSON.stringify(normalizeObserved(operation, observed));
}

function normalizeObserved(operation: Operation, value: unknown): unknown {
  if (operation === "canonical_json" || operation === "stable_hash") {
    if (typeof value !== "string") {
      throw new Error("string probe");
    }
    return value;
  }
  if (operation === "verify_audit_receipt" || operation === "verify_controlled_integrity") {
    if (value !== true) {
      throw new Error("verify probe is not true");
    }
    return true;
  }
  if (!isRecord(value) || typeof value.relationship !== "string" || !isStringArray(value.widened) || !isStringArray(value.narrowed)) {
    throw new Error("compare probe");
  }
  return { relationship: value.relationship, widened: [...value.widened], narrowed: [...value.narrowed] };
}

function parseArgs(argv: readonly string[]): {
  command: "full" | "smoke" | "parse";
  out?: string;
  python: string;
  allowUnpinned: boolean;
  file: string;
} {
  const command = argv[0];
  if (command !== "full" && command !== "smoke" && command !== "parse") {
    usage();
  }
  let out: string | undefined;
  let python = "python3";
  let allowUnpinned = false;
  let file = "";
  for (let index = 1; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--out") {
      out = argv[index + 1];
      index += 1;
      if (!out) {
        usage();
      }
    } else if (flag === "--python") {
      const next = argv[index + 1];
      index += 1;
      if (!next) {
        usage();
      }
      python = next;
    } else if (flag === "--allow-unpinned") {
      allowUnpinned = true;
    } else if (command === "parse" && file.length === 0 && flag && !flag.startsWith("-")) {
      file = flag;
    } else {
      usage();
    }
  }
  if (command === "parse" && file.length === 0) {
    usage();
  }
  if (command === "smoke" && !out) {
    usage();
  }
  return { command, out, python, allowUnpinned, file };
}

function usage(): never {
  console.error("usage: ./bench/run full [--python PYTHON] [--allow-unpinned] [--out FILE]");
  console.error("       ./bench/run smoke --out FILE [--python PYTHON]");
  console.error("       ./bench/run parse FILE");
  process.exit(1);
}

function loadRows(): VectorRow[] {
  const parsed: unknown = JSON.parse(readFileSync(join(root, "vectors/reference/vectors.json"), "utf8"));
  if (!isRecord(parsed) || !Array.isArray(parsed.vectors)) {
    throw new Error("vectors");
  }
  return parsed.vectors.map((row) => {
    if (!isRecord(row) || typeof row.name !== "string" || !("input" in row)) {
      throw new Error("vector row");
    }
    return { name: row.name, input: row.input };
  });
}

function rowNamed(rows: readonly VectorRow[], name: string): VectorRow {
  const found = rows.find((row) => row.name === name);
  if (!found) {
    throw new Error(name);
  }
  return found;
}

function gitMeta(): { sha: string; dirty: boolean } {
  const sha = commandText("git", ["rev-parse", "HEAD"]);
  const status = spawnSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" });
  if (status.status !== 0) {
    throw new Error("git status");
  }
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new Error("git sha");
  }
  return { sha, dirty: status.stdout.trim().length > 0 };
}

function commandText(command: string, args: readonly string[]): string {
  const child = spawnSync(command, args, { cwd: root, encoding: "utf8" });
  if (child.status !== 0) {
    throw new Error(`${command} ${args.join(" ")}`);
  }
  return child.stdout.trim();
}

function cpuModel(): string {
  if (process.platform === "linux") {
    try {
      const text = readFileSync("/proc/cpuinfo", "utf8");
      const line = text.split("\n").find((item) => item.startsWith("model name"));
      if (line) {
        return line.split(":").slice(1).join(":").trim();
      }
    } catch (err) {
      const code = typeof err === "object" && err !== null && "code" in err ? (err as { code: unknown }).code : undefined;
      if (code !== "ENOENT") {
        throw err;
      }
    }
  }
  return cpus()[0]?.model ?? "unknown";
}

function readAllowedCpus(): number[] {
  try {
    const text = readFileSync("/proc/self/status", "utf8");
    const line = text.split("\n").find((item) => item.startsWith("Cpus_allowed_list:"));
    if (!line) {
      return [];
    }
    const spec = line.split(":").slice(1).join(":").trim();
    const cpusFound: number[] = [];
    for (const part of spec.split(",")) {
      const bounds = part.split("-").map((item) => Number(item));
      const start = bounds[0];
      const end = bounds[1] ?? bounds[0];
      if (start === undefined || end === undefined || !Number.isInteger(start) || !Number.isInteger(end)) {
        return [];
      }
      for (let cpu = start; cpu <= end; cpu += 1) {
        cpusFound.push(cpu);
      }
    }
    return cpusFound;
  } catch {
    return [];
  }
}

function findTaskset(): string | undefined {
  const child = spawnSync("which", ["taskset"], { encoding: "utf8" });
  if (child.status !== 0) {
    return undefined;
  }
  const path = child.stdout.trim();
  return path.length > 0 ? path : undefined;
}

function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = Math.imul(state ^ (state >>> 15), state | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), state | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
}

function seededString(rng: () => number, length: number): string {
  const chars = new Array<string>(length);
  for (let index = 0; index < length; index += 1) {
    chars[index] = String.fromCharCode(97 + Math.floor(rng() * 26));
  }
  return chars.join("");
}

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function utf8Length(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

function compareBytes(previous: unknown, next: unknown): number {
  return utf8Length(canonicalJson(previous)) + 1 + utf8Length(canonicalJson(next));
}

function pairOf(payload: unknown): { previous: unknown; next: unknown } {
  if (!isRecord(payload) || !("previous" in payload) || !("next" in payload)) {
    throw new Error("compare payload");
  }
  return { previous: payload.previous, next: payload.next };
}

function snippet(value: unknown): string {
  const text = JSON.stringify(value) ?? "undefined";
  if (text.length > 180) {
    return `${text.slice(0, 180)}...`;
  }
  return text;
}

function minMax(values: readonly number[]): { min: number; max: number } {
  if (values.length === 0) {
    throw new Error("empty spread");
  }
  return { min: Math.min(...values), max: Math.max(...values) };
}

function isVectorName(value: unknown): value is VectorCaseName {
  return typeof value === "string" && (VECTOR_NAMES as readonly string[]).includes(value);
}

function isShape(value: unknown): value is Shape {
  return typeof value === "string" && (SHAPES as readonly string[]).includes(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function needRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(label);
  }
  return value;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  const got = Object.keys(value).sort();
  const want = [...keys].sort();
  if (got.length !== want.length || got.some((key, index) => key !== want[index])) {
    throw new Error(`fields ${got.join(",")}`);
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exit(code);
  },
  (err: unknown) => {
    console.error(err instanceof Error ? (err.stack ?? err.message) : String(err));
    process.exit(1);
  },
);
