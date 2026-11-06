import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  auditSigningKey,
  canonicalJson,
  compareAuthorityContracts,
  controlledSigningKey,
  resignAuditReceipt,
  signControlledIntegrity,
  stableHash,
  verifyAuditReceipt,
  verifyControlledIntegrity,
} from "./index.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const vectorPath = join(root, "vectors", "reference", "vectors.json");

interface VectorRow {
  name: string;
  kind: string;
  input: unknown;
  expected?: unknown;
  expectedError?: unknown;
}

interface Catalog {
  v1Receipt: unknown;
  v1Key: string;
  v2Allowed: unknown;
  v2Denied: unknown;
  v2Key: string;
}

const failures: string[] = [];
let canonicalOk = 0;
let hmacOk = 0;
let compareOk = 0;

const rows = loadRows();
const catalog = loadCatalog(rows);
for (const row of rows) {
  try {
    if (row.kind === "canonicalize") {
      checkCanonicalize(row);
      canonicalOk += 1;
      continue;
    }
    if (row.kind === "controlled-integrity" || row.kind === "audit.verifyAuditReceipt") {
      checkHmacRow(row, catalog);
      hmacOk += 1;
      continue;
    }
    if (row.kind === "compareAuthorityContracts") {
      checkCompare(row);
      compareOk += 1;
      continue;
    }
    failures.push(row.name);
    console.error(`${row.name} unknown kind ${row.kind}`);
  } catch (err) {
    failures.push(row.name);
    const message = err instanceof Error ? err.message : String(err);
    console.error(`${row.name} ${message}`);
  }
}

if (failures.length > 0 || canonicalOk !== 8 || hmacOk !== 8 || compareOk !== 7) {
  for (const name of failures) {
    console.log(name);
  }
  process.exitCode = 1;
} else {
  console.log("ts-baseline canonicalize 8 ok");
  console.log("ts-baseline hmac 8 ok");
  console.log("ts-baseline compare 7 ok");
}

function loadRows(): VectorRow[] {
  const parsed: unknown = JSON.parse(readFileSync(vectorPath, "utf8"));
  const file = asMap(parsed, "vectors");
  const listed = file["vectors"];
  if (!Array.isArray(listed)) {
    throw new Error("vectors");
  }
  const rows: VectorRow[] = [];
  for (const item of listed) {
    if (!isRow(item)) {
      throw new Error("vector row");
    }
    rows.push(item);
  }
  if (file["count"] !== rows.length || rows.length !== 23) {
    throw new Error("vector count");
  }
  return rows;
}

function isRow(value: unknown): value is VectorRow {
  if (!isMap(value)) {
    return false;
  }
  return typeof value["name"] === "string" && typeof value["kind"] === "string" && "input" in value;
}

function loadCatalog(vectors: VectorRow[]): Catalog {
  let v1Receipt: unknown;
  let v1Key: unknown;
  let v2Allowed: unknown;
  let v2Denied: unknown;
  let v2Key: unknown;
  for (const row of vectors) {
    if (!isMap(row.input)) {
      continue;
    }
    const input = row.input;
    if (row.name === "hmac-audit-receipt-valid") {
      v1Receipt = input["receipt"];
      v1Key = input["signingKeyUtf8"];
    }
    if (row.name === "linkage-version-rules") {
      v2Allowed = input["v2AllowedReceipt"];
      v2Denied = input["v2DeniedReceipt"];
      v2Key = input["signingKeyUtf8"];
    }
  }
  if (typeof v1Key !== "string" || typeof v2Key !== "string") {
    throw new Error("catalog");
  }
  return { v1Receipt, v1Key, v2Allowed, v2Denied, v2Key };
}

function checkCanonicalize(row: VectorRow): void {
  const hasExpected = Object.prototype.hasOwnProperty.call(row, "expected");
  const hasError = Object.prototype.hasOwnProperty.call(row, "expectedError");
  if (hasExpected === hasError) {
    throw new Error("needs expected or expectedError");
  }
  if (hasExpected) {
    checkSuccess(row.input, row.expected, row.name);
    return;
  }
  checkRejections(row.input, row.expectedError, row.name);
}

function checkSuccess(value: unknown, expected: unknown, name: string): void {
  const spec = asMap(expected, name);
  const decoded = decode(value);
  const text = canonicalJson(decoded);
  const digest = stableHash(decoded);
  assert.equal(typeof text, "string");
  assert.equal(typeof digest, "string");
  assert.equal(Buffer.from(text, "utf8").toString("hex"), spec["canonicalUtf8Hex"], name);
  assert.equal(digest, spec["stableHash"], name);
  assert.equal(canonicalJson(decoded), text, name);
  assert.equal(stableHash(decoded), digest, name);
}

function checkRejections(value: unknown, expectedError: unknown, name: string): void {
  const input = asMap(value, name);
  const cases = asMap(input["cases"], name);
  const errors = asMap(expectedError, name);
  const caseKeys = Object.keys(cases).sort();
  const errorKeys = Object.keys(errors).sort();
  assert.deepEqual(caseKeys, errorKeys, name);
  assert.ok(caseKeys.length > 0, name);
  for (const label of caseKeys) {
    const spec = asMap(errors[label], `${name} ${label}`);
    assert.equal(spec["type"], "TypeError", `${name} ${label}`);
    assertCode(decode(cases[label]), "type_error");
  }
}

function checkCompare(row: VectorRow): void {
  const hasExpected = Object.prototype.hasOwnProperty.call(row, "expected");
  const hasError = Object.prototype.hasOwnProperty.call(row, "expectedError");
  if (hasExpected === hasError) {
    throw new Error("needs expected or expectedError");
  }
  const input = asMap(row.input, row.name);
  if (hasExpected) {
    const spec = asMap(row.expected, row.name);
    const got = compareAuthorityContracts(input["previous"], input["next"]);
    assert.equal(got.relationship, spec["relationship"], row.name);
    assert.deepEqual(got.widened, spec["widened"], row.name);
    assert.deepEqual(got.narrowed, spec["narrowed"], row.name);
    return;
  }
  const cases = asMap(input["cases"], row.name);
  const expectedError = asMap(row.expectedError, row.name);
  assert.deepEqual(Object.keys(cases).sort(), Object.keys(expectedError).sort(), row.name);
  for (const label of Object.keys(cases)) {
    const spec = asMap(expectedError[label], `${row.name} ${label}`);
    const pair = asMap(cases[label], `${row.name} ${label}`);
    assert.equal(spec["type"], "TypeError", `${row.name} ${label}`);
    assert.throws(
      () => compareAuthorityContracts(pair["previous"], pair["next"]),
      (err: unknown) => {
        if (!(err instanceof TypeError)) {
          return false;
        }
        if (label === "crossVersion") {
          return errorCode(err) === "cross_version";
        }
        return true;
      },
      `${row.name} ${label}`,
    );
  }
}

function checkHmacRow(row: VectorRow, catalog: Catalog): void {
  switch (row.name) {
    case "hmac-controlled-sign-and-verify":
      checkControlled(row);
      return;
    case "hmac-audit-receipt-valid":
      checkAuditValid(row);
      return;
    case "hmac-audit-receipt-failures":
      checkAuditFailures(row, catalog);
      return;
    case "hmac-audit-keyid-swap":
      checkKeyIdSwap(row, catalog);
      return;
    case "hmac-audit-v1-artifact-hash-mismatch":
      checkV1HashMismatch(row, catalog);
      return;
    case "hmac-key-encoding-and-length":
      checkKeyEncoding(row, catalog);
      return;
    case "linkage-version-rules":
      checkLinkage(row, catalog);
      return;
    case "hmac-audit-pre124-restamp":
      checkRestamp(row);
      return;
    default:
      throw new Error(`unimplemented ${row.name}`);
  }
}

function checkControlled(row: VectorRow): void {
  const input = asMap(row.input, row.name);
  const expected = asMap(row.expected, row.name);
  const sign = asMap(asMap(expected["sign"], "sign")["evidence"], "evidence");
  const verify = asMap(expected["verify"], "verify");
  const cases = asMap(input["verifyCases"], "verifyCases");
  const key = input["signingKeyUtf8"];
  const keyId = input["keyId"];
  const value = decode(input["value"]);
  const evidence = signControlledIntegrity(value, key, keyId);
  assert.equal(evidence.integrityDigest, sign["integrityDigest"]);
  for (const [label, want] of Object.entries(verify)) {
    const got =
      label === "tamperedValue"
        ? verifyControlledIntegrity({ a: "y", b: [1, 2] }, key, keyId, cases["valid"])
        : verifyControlledIntegrity(value, key, keyId, cases[label]);
    assert.equal(got, want, label);
  }
}

function checkAuditValid(row: VectorRow): void {
  const input = asMap(row.input, row.name);
  const expected = asMap(row.expected, row.name);
  const key = input["signingKeyUtf8"];
  const receipt = input["receipt"];
  assert.equal(verifyAuditReceipt(receipt, key), expected["result"]);
  const document = structuredClone(receipt);
  deletePath(document, ["integrity", "signature"]);
  assert.equal(stableHash(document), expected["macInputAscii"]);
  assert.equal(signatureOf(resignAuditReceipt(receipt, key)), signatureOf(receipt));
}

function checkAuditFailures(row: VectorRow, catalog: Catalog): void {
  const expected = asMap(row.expected, row.name);
  const tampered = structuredClone(catalog.v1Receipt);
  asMap(tampered, "receipt")["outcome"] = "allowed";
  assert.equal(verifyAuditReceipt(tampered, catalog.v1Key), expected["tamperedOutcome"]);
  assert.equal(
    verifyAuditReceipt(catalog.v1Receipt, "synthetic-audit-key-WRONG-0000000"),
    expected["wrongKey"],
  );
  const upper = structuredClone(catalog.v1Receipt);
  const upperIntegrity = asMap(asMap(upper, "receipt")["integrity"], "integrity");
  const signature = upperIntegrity["signature"];
  if (typeof signature !== "string") {
    throw new Error("signature");
  }
  upperIntegrity["signature"] = signature.toUpperCase();
  assert.equal(verifyAuditReceipt(upper, catalog.v1Key), expected["uppercaseSignature"]);
  const marked = structuredClone(catalog.v1Receipt);
  asMap(marked, "receipt")["authorityPolicyVersion"] = "2";
  assert.equal(
    verifyAuditReceipt(resignAuditReceipt(marked, catalog.v1Key), catalog.v1Key),
    expected["v2DiscriminatorResigned"],
  );
  assert.equal(verifyAuditReceipt(null, catalog.v1Key), expected["nullReceipt"]);
  const missing = structuredClone(catalog.v1Receipt);
  deletePath(missing, ["integrity"]);
  assert.equal(verifyAuditReceipt(missing, catalog.v1Key), expected["missingIntegrity"]);
}

function checkKeyIdSwap(row: VectorRow, catalog: Catalog): void {
  const expected = asMap(row.expected, row.name);
  const swapped = structuredClone(catalog.v1Receipt);
  asMap(asMap(swapped, "receipt")["integrity"], "integrity")["keyId"] = "synthetic-key-b";
  assert.equal(
    verifyAuditReceipt(swapped, catalog.v1Key),
    expected["swappedKeyIdOldSignature"],
  );
  assert.equal(verifyAuditReceipt(catalog.v1Receipt, catalog.v1Key), expected["control_unchanged"]);
}

function checkV1HashMismatch(row: VectorRow, catalog: Catalog): void {
  const expected = asMap(row.expected, row.name);
  const mismatched = structuredClone(catalog.v1Receipt);
  asMap(asMap(asMap(mismatched, "receipt")["artifacts"], "artifacts")["request"], "request")["hash"] =
    "0".repeat(64);
  assert.equal(
    verifyAuditReceipt(resignAuditReceipt(mismatched, catalog.v1Key), catalog.v1Key),
    expected["mismatchReMaced"],
  );
  assert.equal(
    verifyAuditReceipt(resignAuditReceipt(catalog.v1Receipt, catalog.v1Key), catalog.v1Key),
    expected["control_reMacedUnchanged"],
  );
}

function checkKeyEncoding(row: VectorRow, catalog: Catalog): void {
  const expected = asMap(row.expected, row.name);
  assert.equal(
    verifyAuditReceipt(catalog.v1Receipt, Buffer.from(catalog.v1Key, "utf8")),
    expected["keyAsUtf8Bytes"],
  );
  const resigned = resignAuditReceipt(catalog.v1Receipt, "short");
  assert.equal(verifyAuditReceipt(resigned, "short"), expected["fiveCharKey"]);
  assert.throws(
    () => auditSigningKey("short"),
    (err: unknown) => errorMessage(err) === messageAt(expected, "runtimeRejectsShortKey"),
  );
  const eight = "é".repeat(8);
  assert.throws(
    () => auditSigningKey(eight),
    (err: unknown) => errorMessage(err) === messageAt(expected, "runtimeEightNonAsciiChars"),
  );
  controlledSigningKey(eight);
  assert.throws(
    () => controlledSigningKey(Buffer.from("a".repeat(15))),
    (err: unknown) => errorMessage(err) === messageAt(expected, "controlledFifteenByteKey"),
  );
}

function checkLinkage(row: VectorRow, catalog: Catalog): void {
  const expected = asMap(row.expected, row.name);
  assert.equal(verifyAuditReceipt(catalog.v2Allowed, catalog.v2Key), expected["v2AllowedReceipt"]);
  assert.equal(verifyAuditReceipt(catalog.v2Denied, catalog.v2Key), expected["v2DeniedReceipt"]);
  for (const [label, want] of Object.entries(asMap(expected["v2Mutations"], "v2Mutations"))) {
    const mutated = applyV2Mutation(catalog.v2Allowed, label);
    assert.equal(
      verifyAuditReceipt(resignAuditReceipt(mutated, catalog.v2Key), catalog.v2Key),
      want,
      `v2 ${label}`,
    );
  }
  for (const [label, want] of Object.entries(asMap(expected["v1Mutations"], "v1Mutations"))) {
    const mutated = applyV1Mutation(catalog.v1Receipt, label);
    assert.equal(
      verifyAuditReceipt(resignAuditReceipt(mutated, catalog.v1Key), catalog.v1Key),
      want,
      `v1 ${label}`,
    );
  }
}

function checkRestamp(row: VectorRow): void {
  const input = asMap(row.input, row.name);
  const expected = asMap(row.expected, row.name);
  for (const label of ["v1", "v2"]) {
    const sample = asMap(input[label], label);
    const key = sample["signingKeyUtf8"];
    const receipt = sample["receipt"];
    assert.equal(verifyAuditReceipt(receipt, key), expected[`${label}AsIssued`]);
    const restamped = resignAuditReceipt(receipt, key);
    assert.equal(verifyAuditReceipt(restamped, key), expected[`${label}Restamped`]);
    assert.equal(signatureOf(restamped), expected[`${label}RestampedSignature`]);
  }
}

function applyV2Mutation(receipt: unknown, label: string): unknown {
  const next = structuredClone(receipt);
  if (label === "resignedUnchanged_control") {
    return next;
  }
  if (label === "versionTagV1WithMarker2") {
    setPath(next, ["version"], "adaptive-sandbox.audit-receipt/v1");
    return next;
  }
  if (label === "markerRemovedV2Tag") {
    deletePath(next, ["authorityPolicyVersion"]);
    return next;
  }
  if (label === "marker3") {
    setPath(next, ["authorityPolicyVersion"], "3");
    return next;
  }
  if (label === "policyArtifactVersionLabel1") {
    setPath(next, ["artifacts", "policy", "version"], "1");
    return next;
  }
  if (label === "planEnvelopeVersion1") {
    setPath(next, ["artifacts", "plan", "value", "authority", "version"], "1");
    return refreshHashes(next);
  }
  if (label === "planAuthorityHashUppercase") {
    const hash = stringAt(next, ["artifacts", "plan", "value", "authorityHash"]);
    setPath(next, ["artifacts", "plan", "value", "authorityHash"], hash.toUpperCase());
    return next;
  }
  if (label === "artifactHashMismatch") {
    setPath(next, ["artifacts", "policy", "hash"], "0".repeat(64));
    return next;
  }
  if (label === "argumentAuthorityVersion1") {
    setPath(next, ["artifacts", "plan", "value", "argumentAuthority", "version"], "1");
    return refreshHashes(next);
  }
  if (label === "backendMarker1") {
    setPath(next, ["artifacts", "backend", "value", "authorityPolicyVersion"], "1");
    return refreshHashes(next);
  }
  if (label === "backendAuthorityVersion1") {
    setPath(next, ["artifacts", "backend", "value", "authority", "version"], "1");
    return refreshHashes(next);
  }
  if (label.startsWith("policyLayer_") && label.endsWith("_version1")) {
    const layer = label.slice("policyLayer_".length, -"_version1".length);
    setPath(next, ["artifacts", "policy", "value", layer, "version"], "1");
    return refreshHashes(next);
  }
  if (label === "contractGrantsVersion1") {
    setPath(next, ["artifacts", "contract", "value", "authority", "grants", "version"], "1");
    return refreshHashes(next);
  }
  if (label === "requestAgentAuthorityVersion1") {
    setPath(next, ["artifacts", "request", "value", "agent", "authority", "version"], "1");
    return refreshHashes(next);
  }
  if (label === "requestSessionAuthorityVersion1") {
    setPath(next, ["artifacts", "request", "value", "session", "authority", "version"], "1");
    return refreshHashes(next);
  }
  if (label === "grantedDiffersFromEnvelope") {
    setPath(next, ["authority", "granted", "authority", "network"], {});
    return next;
  }
  if (label === "grantedRemoved") {
    deletePath(next, ["authority", "granted", "authority"]);
    return next;
  }
  throw new Error(`unknown v2 mutation ${label}`);
}

function applyV1Mutation(receipt: unknown, label: string): unknown {
  const next = structuredClone(receipt);
  if (label === "resignedUnchanged_control") {
    return next;
  }
  if (label === "versionTagV2NoMarker") {
    setPath(next, ["version"], "adaptive-sandbox.audit-receipt/v2");
    return next;
  }
  if (label === "planEnvelopeVersion2") {
    setPath(next, ["artifacts", "plan", "value", "authority"], { version: "2" });
    return refreshHashes(next);
  }
  if (label === "planEnvelopeVersion1Explicit") {
    setPath(next, ["artifacts", "plan", "value", "authority"], { version: "1" });
    return refreshHashes(next);
  }
  if (label === "grantedVersion2") {
    setPath(next, ["authority", "granted", "authority"], { version: "2" });
    return next;
  }
  throw new Error(`unknown v1 mutation ${label}`);
}

function refreshHashes(receipt: unknown): unknown {
  const artifacts = asMap(asMap(receipt, "receipt")["artifacts"], "artifacts");
  for (const entry of Object.values(artifacts)) {
    const body = asMap(entry, "artifact");
    body["hash"] = stableHash(body["value"]);
  }
  return receipt;
}

function decode(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => decode(item));
  }
  if (isMap(value)) {
    const keys = Object.keys(value);
    if (keys.length === 1 && Object.prototype.hasOwnProperty.call(value, "$js")) {
      return decodeTag(value["$js"]);
    }
    const out: Record<string, unknown> = {};
    for (const key of keys) {
      out[key] = decode(value[key]);
    }
    return out;
  }
  return value;
}

function decodeTag(text: unknown): unknown {
  if (typeof text !== "string") {
    throw new Error("tag is not a string");
  }
  if (text === "-0") {
    return -0;
  }
  if (text === "NaN") {
    return NaN;
  }
  if (text === "Infinity") {
    return Infinity;
  }
  if (text === "-Infinity") {
    return -Infinity;
  }
  if (text === "undefined") {
    return undefined;
  }
  if (text.startsWith("bigint:")) {
    const digits = text.slice("bigint:".length);
    if (!/^[0-9]+$/.test(digits)) {
      throw new Error(`unknown tag ${text}`);
    }
    return BigInt(digits);
  }
  if (text.startsWith("number:")) {
    return parseNumber(text.slice("number:".length));
  }
  throw new Error(`unknown tag ${text}`);
}

function parseNumber(token: string): number {
  if (token === "" || /\s/.test(token) || !/^[-0-9]/.test(token)) {
    throw new Error(`unknown tag number:${token}`);
  }
  const value: unknown = JSON.parse(token);
  if (typeof value !== "number") {
    throw new Error(`unknown tag number:${token}`);
  }
  return value;
}

function assertCode(value: unknown, code: string): void {
  assert.throws(
    () => canonicalJson(value),
    (err: unknown) => {
      assert.equal(errorCode(err), code);
      assert.equal(errorMessage(err), code);
      return true;
    },
  );
  assert.throws(
    () => stableHash(value),
    (err: unknown) => {
      assert.equal(errorCode(err), code);
      return true;
    },
  );
}

function signatureOf(receipt: unknown): string {
  const signature = asMap(asMap(receipt, "receipt")["integrity"], "integrity")["signature"];
  if (typeof signature !== "string") {
    throw new Error("signature");
  }
  return signature;
}

function stringAt(root: unknown, path: string[]): string {
  const value = dive(root, path);
  if (typeof value !== "string") {
    throw new Error(path.join("."));
  }
  return value;
}

function setPath(root: unknown, path: string[], value: unknown): void {
  const key = path[path.length - 1];
  if (key === undefined) {
    throw new Error("path");
  }
  asMap(dive(root, path.slice(0, -1)), path.join("."))[key] = value;
}

function deletePath(root: unknown, path: string[]): void {
  const key = path[path.length - 1];
  if (key === undefined) {
    throw new Error("path");
  }
  delete asMap(dive(root, path.slice(0, -1)), path.join("."))[key];
}

function dive(root: unknown, path: string[]): unknown {
  let current = root;
  for (const key of path) {
    current = asMap(current, key)[key];
  }
  return current;
}

function messageAt(expected: Record<string, unknown>, label: string): string {
  const message = asMap(asMap(expected[label], label)["error"], "error")["message"];
  if (typeof message !== "string") {
    throw new Error(label);
  }
  return message;
}

function errorCode(err: unknown): unknown {
  if (typeof err !== "object" || err === null) {
    return undefined;
  }
  return Reflect.get(err, "code");
}

function errorMessage(err: unknown): unknown {
  return err instanceof Error ? err.message : undefined;
}

function isMap(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asMap(value: unknown, label: string): Record<string, unknown> {
  if (!isMap(value)) {
    throw new Error(label);
  }
  return value;
}
