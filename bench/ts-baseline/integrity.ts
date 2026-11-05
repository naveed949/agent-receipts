import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalBytes, copyHost, fail, hashTree, isRecord, objectFrom } from "./host.ts";
import type { HostJson, JsonObject } from "./host.ts";

const AUDIT_V1 = "adaptive-sandbox.audit-receipt/v1";
const AUDIT_V2 = "adaptive-sandbox.audit-receipt/v2";
const CONTROLLED_V1 = "controlled-integrity/v1";
const MIN_SIGNER_UNITS = 16;

const POLICY_LAYERS = ["outer", "agent", "session", "state"];
const REQUEST_ACTORS = ["agent", "session"];

export interface ControlledEvidence {
  integrityVersion: string;
  integrityKeyId: string;
  integrityDigest: string;
}

interface KeyMaterial {
  bytes: Buffer;
  auditUnits: number;
}

export function auditSigningKey(key: unknown): Buffer {
  const material = readMaterial(key);
  if (material === undefined) {
    fail("type_error");
  }
  if (material.auditUnits < MIN_SIGNER_UNITS) {
    throw statusError("TypeError", "audit signingKey must contain at least 16 bytes");
  }
  return material.bytes;
}

export function controlledSigningKey(key: unknown): Buffer {
  const material = readMaterial(key);
  if (material === undefined) {
    fail("type_error");
  }
  if (material.bytes.length < MIN_SIGNER_UNITS) {
    throw statusError(
      "RangeError",
      "controlled integrity signing key must contain at least 16 bytes",
    );
  }
  return material.bytes;
}

export function verifyAuditReceipt(receipt: unknown, key: unknown): boolean {
  try {
    return verifyAudit(receipt, key);
  } catch {
    return false;
  }
}

export function resignAuditReceipt(receipt: unknown, key: unknown): HostJson {
  const material = readMaterial(key);
  if (material === undefined) {
    fail("type_error");
  }
  const tree = copyHost(receipt);
  if (!isRecord(tree)) {
    fail("type_error");
  }
  const macInput = auditMacInput(tree);
  if (macInput === undefined) {
    fail("type_error");
  }
  const signature = hmacHex(material.bytes, Buffer.from(macInput, "ascii"));
  return setSignature(tree, signature);
}

export function verifyControlledIntegrity(
  value: unknown,
  key: unknown,
  keyId: unknown,
  evidence: unknown,
): boolean {
  try {
    return verifyControlled(value, key, keyId, evidence);
  } catch {
    return false;
  }
}

export function signControlledIntegrity(
  value: unknown,
  key: unknown,
  keyId: unknown,
): ControlledEvidence {
  const tree = copyHost(value);
  const material = readMaterial(key);
  if (material === undefined) {
    fail("type_error");
  }
  if (typeof keyId !== "string" || !validControlledKeyId(keyId)) {
    throw statusError("TypeError", "invalid key id");
  }
  return {
    integrityVersion: CONTROLLED_V1,
    integrityKeyId: keyId,
    integrityDigest: hmacHex(material.bytes, canonicalBytes(tree)),
  };
}

function verifyAudit(receipt: unknown, key: unknown): boolean {
  const material = readMaterial(key);
  if (material === undefined) {
    return false;
  }
  const tree = copyHost(receipt);
  if (!isRecord(tree)) {
    return false;
  }
  const macInput = auditMacInput(tree);
  if (macInput === undefined) {
    return false;
  }
  const integrity = tree["integrity"];
  if (!isRecord(integrity)) {
    return false;
  }
  const offered = decodeHex64(integrity["signature"]);
  if (offered === undefined) {
    return false;
  }
  if (!macMatches(material.bytes, Buffer.from(macInput, "ascii"), offered)) {
    return false;
  }
  return artifactHashesMatch(tree) && linkageOk(tree);
}

function verifyControlled(
  value: unknown,
  key: unknown,
  keyId: unknown,
  evidence: unknown,
): boolean {
  if (typeof keyId !== "string") {
    return false;
  }
  const material = readMaterial(key);
  if (material === undefined) {
    return false;
  }
  const body = copyHost(value);
  const proof = copyHost(evidence);
  if (!isRecord(proof)) {
    return false;
  }
  if (proof["integrityVersion"] !== CONTROLLED_V1) {
    return false;
  }
  if (proof["integrityKeyId"] !== keyId) {
    return false;
  }
  const offered = decodeHex64(proof["integrityDigest"]);
  if (offered === undefined) {
    return false;
  }
  return macMatches(material.bytes, canonicalBytes(body), offered);
}

function auditMacInput(receipt: JsonObject): string | undefined {
  const version = textAt(receipt, ["version"]);
  if (version !== AUDIT_V1 && version !== AUDIT_V2) {
    return undefined;
  }
  const integrity = receipt["integrity"];
  if (!isRecord(integrity) || integrity["algorithm"] !== "hmac-sha256") {
    return undefined;
  }
  const keyId = integrity["keyId"];
  if (typeof keyId !== "string" || keyId.length === 0 || keyId.trim() !== keyId) {
    return undefined;
  }
  const document = removeSignature(receipt);
  if (document === undefined) {
    return undefined;
  }
  const hash = hashTree(document);
  if (!isHex64(hash)) {
    return undefined;
  }
  return hash;
}

function removeSignature(receipt: JsonObject): JsonObject | undefined {
  const integrity = receipt["integrity"];
  if (!isRecord(integrity)) {
    return undefined;
  }
  const entries: Array<[string, HostJson]> = [];
  for (const key of Object.keys(receipt)) {
    if (key !== "integrity") {
      entries.push([key, receipt[key]]);
    }
  }
  const stripped: Array<[string, HostJson]> = [];
  for (const key of Object.keys(integrity)) {
    if (key !== "signature") {
      stripped.push([key, integrity[key]]);
    }
  }
  entries.push(["integrity", objectFrom(stripped)]);
  return objectFrom(entries);
}

function setSignature(receipt: JsonObject, signature: string): JsonObject {
  const integrity = receipt["integrity"];
  if (!isRecord(integrity)) {
    fail("type_error");
  }
  const entries: Array<[string, HostJson]> = [];
  let replaced = false;
  for (const key of Object.keys(integrity)) {
    if (key === "signature") {
      entries.push([key, signature]);
      replaced = true;
    } else {
      entries.push([key, integrity[key]]);
    }
  }
  if (!replaced) {
    entries.push(["signature", signature]);
  }
  const root: Array<[string, HostJson]> = [];
  for (const key of Object.keys(receipt)) {
    if (key === "integrity") {
      root.push([key, objectFrom(entries)]);
    } else {
      root.push([key, receipt[key]]);
    }
  }
  return objectFrom(root);
}

function artifactHashesMatch(receipt: JsonObject): boolean {
  const artifacts = receipt["artifacts"];
  if (!isRecord(artifacts)) {
    return false;
  }
  for (const name of Object.keys(artifacts)) {
    const entry = artifacts[name];
    if (!isRecord(entry) || typeof entry["hash"] !== "string" || !Object.hasOwn(entry, "value")) {
      return false;
    }
    try {
      if (hashTree(entry["value"]) !== entry["hash"]) {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

function linkageOk(receipt: JsonObject): boolean {
  if (Object.hasOwn(receipt, "authorityPolicyVersion")) {
    return v2Linkage(receipt);
  }
  return v1Linkage(receipt);
}

function v1Linkage(receipt: JsonObject): boolean {
  if (textAt(receipt, ["version"]) !== AUDIT_V1) {
    return false;
  }
  if (Object.hasOwn(receipt, "gondolinHttps")) {
    return false;
  }
  return versionAbsentOr(envelope(receipt), "1") && grantedV1(receipt);
}

function v2Linkage(receipt: JsonObject): boolean {
  if (textAt(receipt, ["version"]) !== AUDIT_V2) {
    return false;
  }
  if (textAt(receipt, ["authorityPolicyVersion"]) !== "2") {
    return false;
  }
  if (textAt(receipt, ["artifacts", "policy", "version"]) !== "2") {
    return false;
  }
  const plan = at(receipt, ["artifacts", "plan", "value"]);
  if (!isRecord(plan)) {
    return false;
  }
  const envelopeValue = plan["authority"];
  if (!isRecord(envelopeValue) || envelopeValue["version"] !== "2") {
    return false;
  }
  if (!isHex64(typeof plan["authorityHash"] === "string" ? plan["authorityHash"] : undefined)) {
    return false;
  }
  if (!artifactHashesMatch(receipt)) {
    return false;
  }
  const argument = plan["argumentAuthority"];
  if (!isRecord(argument) || argument["version"] !== "2") {
    return false;
  }
  const backend = at(receipt, ["artifacts", "backend", "value"]);
  if (!isRecord(backend) || backend["authorityPolicyVersion"] !== "2") {
    return false;
  }
  const backendAuthority = backend["authority"];
  if (!isRecord(backendAuthority) || backendAuthority["version"] !== "2") {
    return false;
  }
  const policy = at(receipt, ["artifacts", "policy", "value"]);
  if (!isRecord(policy)) {
    return false;
  }
  for (const layer of POLICY_LAYERS) {
    const body = policy[layer];
    if (!isRecord(body) || body["version"] !== "2") {
      return false;
    }
  }
  const grants = at(receipt, ["artifacts", "contract", "value", "authority", "grants"]);
  if (!isRecord(grants) || grants["version"] !== "2") {
    return false;
  }
  const request = at(receipt, ["artifacts", "request", "value"]);
  if (!isRecord(request)) {
    return false;
  }
  for (const actor of REQUEST_ACTORS) {
    const actorBody = request[actor];
    if (!isRecord(actorBody)) {
      return false;
    }
    const authority = actorBody["authority"];
    if (!isRecord(authority) || authority["version"] !== "2") {
      return false;
    }
  }
  return grantedV2(receipt, envelopeValue);
}

function envelope(receipt: JsonObject): JsonObject | undefined {
  const plan = at(receipt, ["artifacts", "plan", "value"]);
  if (!isRecord(plan)) {
    return undefined;
  }
  const authority = plan["authority"];
  return isRecord(authority) ? authority : undefined;
}

function grantedAuthority(receipt: JsonObject): HostJson | undefined {
  return at(receipt, ["authority", "granted", "authority"]);
}

function grantedV1(receipt: JsonObject): boolean {
  const granted = grantedAuthority(receipt);
  if (!isRecord(granted)) {
    return true;
  }
  return versionAbsentOr(granted, "1");
}

function grantedV2(receipt: JsonObject, envelopeValue: JsonObject): boolean {
  const granted = grantedAuthority(receipt);
  if (granted === undefined) {
    return true;
  }
  if (!isRecord(granted) || granted["version"] !== "2") {
    return false;
  }
  try {
    return hashTree(granted) === hashTree(envelopeValue);
  } catch {
    return false;
  }
}

function versionAbsentOr(value: JsonObject | undefined, allowed: string): boolean {
  if (value === undefined || !Object.hasOwn(value, "version")) {
    return true;
  }
  return value["version"] === allowed;
}

function at(root: HostJson, path: string[]): HostJson | undefined {
  let current: HostJson | undefined = root;
  for (const name of path) {
    if (current === undefined || !isRecord(current) || !Object.hasOwn(current, name)) {
      return undefined;
    }
    current = current[name];
  }
  return current;
}

function textAt(root: HostJson, path: string[]): string | undefined {
  const value = at(root, path);
  return typeof value === "string" ? value : undefined;
}

function readMaterial(key: unknown): KeyMaterial | undefined {
  if (typeof key === "string") {
    return { bytes: Buffer.from(key, "utf8"), auditUnits: key.length };
  }
  if (key instanceof Uint8Array) {
    const bytes = Buffer.from(key);
    return { bytes, auditUnits: bytes.length };
  }
  return undefined;
}

function validControlledKeyId(keyId: string): boolean {
  if (keyId.length === 0 || keyId.length > 128) {
    return false;
  }
  if (!isAsciiAlnum(keyId.charCodeAt(0))) {
    return false;
  }
  for (let index = 1; index < keyId.length; index += 1) {
    const unit = keyId.charCodeAt(index);
    if (isAsciiAlnum(unit)) {
      continue;
    }
    if (unit === 0x2e || unit === 0x5f || unit === 0x3a || unit === 0x2d) {
      continue;
    }
    return false;
  }
  return true;
}

function isAsciiAlnum(unit: number): boolean {
  const digit = unit >= 0x30 && unit <= 0x39;
  const upper = unit >= 0x41 && unit <= 0x5a;
  const lower = unit >= 0x61 && unit <= 0x7a;
  return digit || upper || lower;
}

function hmacDigest(key: Buffer, data: Buffer): Buffer {
  return createHmac("sha256", key).update(data).digest();
}

function hmacHex(key: Buffer, data: Buffer): string {
  return hmacDigest(key, data).toString("hex");
}

function macMatches(key: Buffer, data: Buffer, offered: Buffer): boolean {
  const actual = hmacDigest(key, data);
  if (actual.length !== offered.length) {
    return false;
  }
  return timingSafeEqual(actual, offered);
}

function decodeHex64(value: unknown): Buffer | undefined {
  if (typeof value !== "string" || value.length !== 64) {
    return undefined;
  }
  const out = Buffer.alloc(32);
  for (let index = 0; index < 32; index += 1) {
    const hi = nibble(value.charCodeAt(index * 2));
    const lo = nibble(value.charCodeAt(index * 2 + 1));
    if (hi === undefined || lo === undefined) {
      return undefined;
    }
    out[index] = (hi << 4) | lo;
  }
  return out;
}

function nibble(unit: number): number | undefined {
  if (unit >= 0x30 && unit <= 0x39) {
    return unit - 0x30;
  }
  if (unit >= 0x61 && unit <= 0x66) {
    return unit - 0x61 + 10;
  }
  return undefined;
}

function isHex64(value: string | undefined): boolean {
  return decodeHex64(value) !== undefined;
}

function statusError(status: "TypeError" | "RangeError", message: string): Error {
  const err = status === "RangeError" ? new RangeError(message) : new TypeError(message);
  Reflect.set(err, "code", status);
  return err;
}
