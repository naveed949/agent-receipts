import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const PINNED = "70507a2b636c05bf9841cb99921ff91908cd5e2ab7e270b14802f32727bbb7c1";
const DIGEST = "ab".repeat(32);
const FAKE_SHA = "cd".repeat(32);
const IMPLEMENTATIONS = ["typescript", "node_napi", "python_abi3", "rust_native"] as const;
const OPERATIONS = [
  "canonical_json",
  "stable_hash",
  "verify_audit_receipt",
  "verify_controlled_integrity",
  "compare_authority_contracts",
] as const;
const VECTOR_NAME = {
  canonical_json: "canon-key-order-nested",
  stable_hash: "canon-key-order-nested",
  verify_audit_receipt: "hmac-audit-receipt-valid",
  verify_controlled_integrity: "hmac-controlled-sign-and-verify",
  compare_authority_contracts: "cmp-v1-mixed-and-order",
} as const;
const SYNTHETIC = {
  canonical_json: { shape: "object_tree", budgets: [8192, 65536, 524288] },
  stable_hash: { shape: "object_tree", budgets: [8192, 65536, 524288] },
  verify_audit_receipt: { shape: "audit_receipt", budgets: [8192, 65536] },
  verify_controlled_integrity: { shape: "controlled_value", budgets: [8192, 65536] },
  compare_authority_contracts: { shape: "authority_pair", budgets: [4096, 32768] },
} as const;

const outDir = process.argv[2];
if (outDir === undefined) {
  throw new Error("usage: parse-repro.ts DIR");
}
mkdirSync(outDir, { recursive: true });

const zerosPath = join(outDir, "zeros.json");
writeFileSync(zerosPath, `${JSON.stringify(smokeFile({ samples: [0, 0, 0, 0, 0], sha: PINNED }))}\n`);
expectReject(zerosPath, "all-zero");

const fakeShaPath = join(outDir, "fake-sha.json");
writeFileSync(
  fakeShaPath,
  `${JSON.stringify(smokeFile({ samples: [1, 2, 3, 4, 5], sha: FAKE_SHA }))}\n`,
);
expectReject(fakeShaPath, "fake-sha");

const smokeAsFull = join(outDir, "full.json");
writeFileSync(
  smokeAsFull,
  `${JSON.stringify(smokeFile({ samples: [1, 2, 3, 4, 5], sha: PINNED }))}\n`,
);
expectReject(smokeAsFull, "full.json-smoke-mode");

const smokeEffortFull = join(outDir, "full-mode-smoke-effort.json");
writeFileSync(
  smokeEffortFull,
  `${JSON.stringify(fullFile({ samples: [1, 2, 3, 4, 5], sha: PINNED }))}\n`,
);
expectReject(smokeEffortFull, "full-mode-smoke-effort");

console.log("parse-repro ok");

function expectReject(path: string, label: string): void {
  const child = spawnSync(join(root, "bench/run"), ["parse", path], { encoding: "utf8" });
  if (child.status === 0) {
    process.stderr.write(child.stdout ?? "");
    process.stderr.write(child.stderr ?? "");
    throw new Error(`${label} parse exited 0`);
  }
  console.log(`${label} exit ${child.status}`);
}

function smokeFile(opts: { samples: number[]; sha: string }) {
  return resultsFile("smoke", 1, planned("smoke"), opts);
}

function fullFile(opts: { samples: number[]; sha: string }) {
  return resultsFile("full", 5, planned("full"), opts);
}

function planned(mode: "full" | "smoke"): { operation: string; caseId: object }[] {
  const cases: { operation: string; caseId: object }[] = [];
  for (const operation of OPERATIONS) {
    cases.push({ operation, caseId: { source: "vector", name: VECTOR_NAME[operation] } });
    if (mode === "full") {
      const spec = SYNTHETIC[operation];
      for (const budget of spec.budgets) {
        cases.push({ operation, caseId: { source: "synthetic", shape: spec.shape, budget } });
      }
    }
  }
  return cases;
}

function resultsFile(
  mode: "full" | "smoke",
  runs: number,
  cases: { operation: string; caseId: object }[],
  opts: { samples: number[]; sha: string },
) {
  return {
    schema: 1,
    mode,
    environment: {
      recordedAt: "2026-11-05T00:00:00.000Z",
      gitSha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      gitDirty: false,
      rustc: "1.83.0",
      cargoProfile: "release",
      node: "v22.23.4",
      python: "3.12.3",
      pythonModule: "/tmp/site-packages/agent_receipts",
      nodeAddon: "bindings/node/index.js",
      rustBin: "bench/rust-native/target/release/agent-receipts-bench-native",
      os: "Linux",
      arch: "x64",
      cpuModel: "test-cpu",
      affinity: { status: "pinned", cpu: 0 },
      runs,
      isolate: "process",
      gcInTimedRegion: false,
      vectorsSha256: opts.sha,
    },
    vectorGate: { status: "passed", canonicalize: 8, hmac: 8, compare: 7 },
    runs: Array.from({ length: runs }, (_, runIndex) => ({
      runIndex,
      series: IMPLEMENTATIONS.flatMap((implementation) =>
        cases.map((item) => ({
          implementation,
          operation: item.operation,
          caseId: item.caseId,
          inputDigest: DIGEST,
          samplesNs: opts.samples,
        })),
      ),
    })),
  };
}
