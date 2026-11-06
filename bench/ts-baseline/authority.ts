import { canonicalBytes, copyHost, isRecord, objectFrom } from "./host.ts";
import type { HostJson, JsonObject } from "./host.ts";

const MAX_SAFE_INT = 9007199254740991;
const TOP_FIELDS = [
  "version",
  "filesystem",
  "network",
  "git",
  "environment",
  "output",
  "container",
];
const FILESYSTEM_FIELDS = ["read", "sensitiveRead", "write"];
const GIT_FIELDS = ["write", "hooks"];
const ENVIRONMENT_FIELDS = ["secrets", "ambientSecrets"];
const OUTPUT_FIELDS = ["unrestricted"];
const CONTAINER_FIELDS = ["socket"];
const HTTPS_FIELDS = [
  "protocol",
  "host",
  "port",
  "methods",
  "resolution",
  "redirects",
  "maxResponseBytes",
  "timeoutMs",
];
const METHOD_NAMES: Method[] = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"];

type AuthorityCode =
  | "not_an_object"
  | "cross_version"
  | "unsupported_version"
  | "unknown_field"
  | "https_in_v1"
  | "outbound_in_v2"
  | "invalid_scope"
  | "invalid_flag"
  | "invalid_https_host"
  | "invalid_https_port"
  | "invalid_https_method"
  | "invalid_https_bounds"
  | "invalid_https_shape";

type Path =
  | "filesystem.read"
  | "filesystem.sensitiveRead"
  | "filesystem.write"
  | "network.outbound"
  | "network.https"
  | "git.write"
  | "git.hooks"
  | "environment.secrets"
  | "environment.ambientSecrets"
  | "output.unrestricted"
  | "container.socket";

const PATHS: Path[] = [
  "filesystem.read",
  "filesystem.sensitiveRead",
  "filesystem.write",
  "network.outbound",
  "network.https",
  "git.write",
  "git.hooks",
  "environment.secrets",
  "environment.ambientSecrets",
  "output.unrestricted",
  "container.socket",
];

type Method = "DELETE" | "GET" | "HEAD" | "OPTIONS" | "PATCH" | "POST" | "PUT";

interface ScopeAny {
  kind: "any";
}

interface ScopeIds {
  kind: "ids";
  ids: string[];
}

type Scope = ScopeAny | ScopeIds;

interface HttpsRule {
  protocol: "https";
  host: string;
  port: number;
  methods: Method[];
  resolution: "public-only";
  redirects: "none";
  maxResponseBytes: number;
  timeoutMs: number;
}

interface NetworkV1 {
  kind: "v1";
  outbound: Scope;
}

interface NetworkV2 {
  kind: "v2";
  https: HttpsRule[];
}

interface Policy {
  version: 1 | 2;
  filesystem: { read: Scope; sensitiveRead: Scope; write: Scope };
  network: NetworkV1 | NetworkV2;
  git: { write: Scope; hooks: Scope };
  environment: { secrets: Scope; ambientSecrets: boolean };
  output: { unrestricted: boolean };
  container: { socket: boolean };
}

interface Change {
  wide: boolean;
  narrow: boolean;
}

export interface CompareResult {
  relationship: "widening" | "narrowing" | "mixed" | "unchanged";
  widened: string[];
  narrowed: string[];
}

export function compareAuthorityContracts(previous: unknown, next: unknown): CompareResult {
  const left = parsePolicy(copyHost(previous));
  const right = parsePolicy(copyHost(next));
  if (left.version !== right.version) {
    authorityFail("cross_version");
  }
  const widened: string[] = [];
  const narrowed: string[] = [];
  for (const path of PATHS) {
    const change = changeAt(left, right, path);
    if (change.wide) {
      widened.push(path);
    }
    if (change.narrow) {
      narrowed.push(path);
    }
  }
  const relationship = relate(widened, narrowed);
  return Object.freeze({
    relationship,
    widened: Object.freeze(widened),
    narrowed: Object.freeze(narrowed),
  });
}

function relate(widened: string[], narrowed: string[]): CompareResult["relationship"] {
  if (widened.length > 0 && narrowed.length > 0) {
    return "mixed";
  }
  if (widened.length > 0) {
    return "widening";
  }
  if (narrowed.length > 0) {
    return "narrowing";
  }
  return "unchanged";
}

function changeAt(previous: Policy, next: Policy, path: Path): Change {
  switch (path) {
    case "filesystem.read":
      return compareScope(previous.filesystem.read, next.filesystem.read);
    case "filesystem.sensitiveRead":
      return compareScope(previous.filesystem.sensitiveRead, next.filesystem.sensitiveRead);
    case "filesystem.write":
      return compareScope(previous.filesystem.write, next.filesystem.write);
    case "network.outbound":
      return compareScope(outboundScope(previous), outboundScope(next));
    case "network.https":
      return compareHttps(previous, next);
    case "git.write":
      return compareScope(previous.git.write, next.git.write);
    case "git.hooks":
      return compareScope(previous.git.hooks, next.git.hooks);
    case "environment.secrets":
      return compareScope(previous.environment.secrets, next.environment.secrets);
    case "environment.ambientSecrets":
      return compareFlag(
        previous.environment.ambientSecrets,
        next.environment.ambientSecrets,
      );
    case "output.unrestricted":
      return compareFlag(previous.output.unrestricted, next.output.unrestricted);
    case "container.socket":
      return compareFlag(previous.container.socket, next.container.socket);
    default: {
      const neverPath: never = path;
      throw new Error(neverPath);
    }
  }
}

function compareScope(before: Scope, after: Scope): Change {
  if (before.kind === "any" && after.kind === "any") {
    return { wide: false, narrow: false };
  }
  if (after.kind === "any") {
    return { wide: true, narrow: false };
  }
  if (before.kind === "any") {
    return { wide: false, narrow: true };
  }
  const beforeSet = new Set(before.ids);
  const afterSet = new Set(after.ids);
  return {
    wide: after.ids.some((item) => !beforeSet.has(item)),
    narrow: before.ids.some((item) => !afterSet.has(item)),
  };
}

function compareFlag(before: boolean, after: boolean): Change {
  return { wide: after && !before, narrow: before && !after };
}

function compareHttps(previous: Policy, next: Policy): Change {
  const before = httpsRules(previous);
  const after = httpsRules(next);
  return {
    wide: !httpsSubset(after, before),
    narrow: !httpsSubset(before, after),
  };
}

function outboundScope(policy: Policy): Scope {
  if (policy.network.kind === "v1") {
    return policy.network.outbound;
  }
  return emptyScope();
}

function httpsRules(policy: Policy): HttpsRule[] {
  if (policy.network.kind === "v2") {
    return policy.network.https;
  }
  return [];
}

function httpsSubset(inner: HttpsRule[], outer: HttpsRule[]): boolean {
  return inner.every((rule) =>
    rule.methods.every((method) => outer.some((cover) => methodCovered(cover, rule, method))),
  );
}

function methodCovered(cover: HttpsRule, inner: HttpsRule, method: Method): boolean {
  return (
    cover.protocol === inner.protocol &&
    cover.host === inner.host &&
    cover.port === inner.port &&
    cover.resolution === inner.resolution &&
    cover.redirects === inner.redirects &&
    cover.methods.includes(method) &&
    cover.maxResponseBytes >= inner.maxResponseBytes &&
    cover.timeoutMs >= inner.timeoutMs
  );
}

function parsePolicy(value: HostJson): Policy {
  if (!isRecord(value)) {
    authorityFail("not_an_object");
  }
  rejectUnknown(value, TOP_FIELDS);
  const version = parseVersion(read(value, "version"));
  const filesystem = domain(read(value, "filesystem"), FILESYSTEM_FIELDS);
  const git = domain(read(value, "git"), GIT_FIELDS);
  const environment = domain(read(value, "environment"), ENVIRONMENT_FIELDS);
  const output = domain(read(value, "output"), OUTPUT_FIELDS);
  const container = domain(read(value, "container"), CONTAINER_FIELDS);
  return {
    version,
    filesystem: {
      read: parseScope(readDomain(filesystem, "read")),
      sensitiveRead: parseScope(readDomain(filesystem, "sensitiveRead")),
      write: parseScope(readDomain(filesystem, "write")),
    },
    network: parseNetwork(read(value, "network"), version),
    git: {
      write: parseScope(readDomain(git, "write")),
      hooks: parseScope(readDomain(git, "hooks")),
    },
    environment: {
      secrets: parseScope(readDomain(environment, "secrets")),
      ambientSecrets: parseFlag(readDomain(environment, "ambientSecrets")),
    },
    output: {
      unrestricted: parseFlag(readDomain(output, "unrestricted")),
    },
    container: {
      socket: parseFlag(readDomain(container, "socket")),
    },
  };
}

function parseVersion(value: HostJson | undefined): 1 | 2 {
  if (value === undefined || value === "1") {
    return 1;
  }
  if (value === "2") {
    return 2;
  }
  authorityFail("unsupported_version");
}

function parseNetwork(value: HostJson | undefined, version: 1 | 2): NetworkV1 | NetworkV2 {
  if (value === undefined) {
    if (version === 1) {
      return { kind: "v1", outbound: emptyScope() };
    }
    return { kind: "v2", https: [] };
  }
  if (!isRecord(value)) {
    authorityFail("not_an_object");
  }
  if (version === 1) {
    if (Object.hasOwn(value, "https")) {
      authorityFail("https_in_v1");
    }
    rejectUnknown(value, ["outbound"]);
    return { kind: "v1", outbound: parseScope(read(value, "outbound")) };
  }
  if (Object.hasOwn(value, "outbound")) {
    authorityFail("outbound_in_v2");
  }
  rejectUnknown(value, ["https"]);
  const https = read(value, "https");
  return { kind: "v2", https: https === undefined ? [] : parseHttpsRules(https) };
}

function domain(value: HostJson | undefined, allowed: string[]): JsonObject | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    authorityFail("not_an_object");
  }
  rejectUnknown(value, allowed);
  return value;
}

function parseScope(value: HostJson | undefined): Scope {
  if (value === undefined) {
    return emptyScope();
  }
  if (typeof value === "string") {
    if (value === "any") {
      return { kind: "any" };
    }
    authorityFail("invalid_scope");
  }
  if (!Array.isArray(value)) {
    authorityFail("invalid_scope");
  }
  const ids: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || item.length === 0 || item.trim() !== item) {
      authorityFail("invalid_scope");
    }
    ids.push(item);
  }
  ids.sort(compareUtf16);
  const unique: string[] = [];
  for (const id of ids) {
    const last = unique.length === 0 ? undefined : unique[unique.length - 1];
    if (last !== id) {
      unique.push(id);
    }
  }
  return { kind: "ids", ids: unique };
}

function parseFlag(value: HostJson | undefined): boolean {
  if (value === undefined) {
    return false;
  }
  if (typeof value !== "boolean") {
    authorityFail("invalid_flag");
  }
  return value;
}

function parseHttpsRules(value: HostJson): HttpsRule[] {
  if (!Array.isArray(value)) {
    authorityFail("invalid_https_shape");
  }
  const rules: HttpsRule[] = [];
  for (const item of value) {
    rules.push(parseHttpsRule(item));
  }
  return normalizeHttps(rules);
}

function parseHttpsRule(value: HostJson): HttpsRule {
  if (!isRecord(value) || Object.keys(value).length !== HTTPS_FIELDS.length) {
    authorityFail("invalid_https_shape");
  }
  rejectUnknown(value, HTTPS_FIELDS);
  if (requireString(value, "protocol") !== "https") {
    authorityFail("invalid_https_shape");
  }
  if (requireString(value, "resolution") !== "public-only") {
    authorityFail("invalid_https_shape");
  }
  if (requireString(value, "redirects") !== "none") {
    authorityFail("invalid_https_shape");
  }
  const port = read(value, "port");
  const methods = read(value, "methods");
  const maxResponseBytes = read(value, "maxResponseBytes");
  const timeoutMs = read(value, "timeoutMs");
  if (
    port === undefined ||
    methods === undefined ||
    maxResponseBytes === undefined ||
    timeoutMs === undefined
  ) {
    authorityFail("invalid_https_shape");
  }
  return {
    protocol: "https",
    host: parseHost(requireString(value, "host")),
    port: parsePort(port),
    methods: parseMethods(methods),
    resolution: "public-only",
    redirects: "none",
    maxResponseBytes: parsePositiveSafe(maxResponseBytes),
    timeoutMs: parsePositiveSafe(timeoutMs),
  };
}

function parseHost(raw: string): string {
  if (raw.length === 0 || !isAscii(raw) || raw.startsWith(".") || raw.endsWith(".")) {
    authorityFail("invalid_https_host");
  }
  if (raw.includes(":") || raw.includes("/") || raw.includes("@")) {
    authorityFail("invalid_https_host");
  }
  const lower = raw.toLowerCase();
  const labels = lower.split(".");
  if (labels.length < 2) {
    authorityFail("invalid_https_host");
  }
  const last = labels.length - 1;
  for (let index = 0; index < labels.length; index += 1) {
    const label = labels[index];
    if (label === undefined || label.length === 0 || label.length > 63 || label.startsWith("xn--")) {
      authorityFail("invalid_https_host");
    }
    if (index === last) {
      if (!isAlphabetic(label)) {
        authorityFail("invalid_https_host");
      }
    } else if (!isLdh(label)) {
      authorityFail("invalid_https_host");
    }
  }
  return lower;
}

function parsePort(value: HostJson): number {
  const number = exactInt(value);
  if (number === undefined || number < 1 || number > 65535) {
    authorityFail("invalid_https_port");
  }
  return number;
}

function parsePositiveSafe(value: HostJson): number {
  const number = exactInt(value);
  if (number === undefined || number < 1 || number > MAX_SAFE_INT) {
    authorityFail("invalid_https_bounds");
  }
  return number;
}

function exactInt(value: HostJson): number | undefined {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    return undefined;
  }
  return value;
}

function parseMethods(value: HostJson): Method[] {
  if (!Array.isArray(value) || value.length === 0) {
    authorityFail("invalid_https_method");
  }
  const present = new Set<Method>();
  for (const item of value) {
    if (typeof item !== "string" || !isMethod(item)) {
      authorityFail("invalid_https_method");
    }
    present.add(item);
  }
  const methods: Method[] = [];
  for (const name of METHOD_NAMES) {
    if (present.has(name)) {
      methods.push(name);
    }
  }
  return methods;
}

function normalizeHttps(rules: HttpsRule[]): HttpsRule[] {
  const unique = dedupRules(sortRules(rules));
  const kept: HttpsRule[] = [];
  for (let index = 0; index < unique.length; index += 1) {
    const rule = unique[index];
    if (rule === undefined) {
      continue;
    }
    const covered = unique.some((cover, other) => other !== index && ruleCovers(cover, rule));
    if (!covered) {
      kept.push(rule);
    }
  }
  return sortRules(kept);
}

function sortRules(rules: HttpsRule[]): HttpsRule[] {
  return rules
    .map((rule) => ({ rule, key: canonicalBytes(ruleJson(rule)).toString("utf8") }))
    .sort((left, right) => compareUtf16(left.key, right.key))
    .map((item) => item.rule);
}

function dedupRules(rules: HttpsRule[]): HttpsRule[] {
  const out: HttpsRule[] = [];
  let previous = "";
  for (const rule of rules) {
    const key = canonicalBytes(ruleJson(rule)).toString("utf8");
    if (key === previous) {
      continue;
    }
    previous = key;
    out.push(rule);
  }
  return out;
}

function ruleCovers(cover: HttpsRule, inner: HttpsRule): boolean {
  return inner.methods.every((method) => methodCovered(cover, inner, method));
}

function ruleJson(rule: HttpsRule): JsonObject {
  const methods: HostJson[] = [];
  for (const method of rule.methods) {
    methods.push(method);
  }
  return objectFrom([
    ["protocol", rule.protocol],
    ["host", rule.host],
    ["port", rule.port],
    ["methods", methods],
    ["resolution", rule.resolution],
    ["redirects", rule.redirects],
    ["maxResponseBytes", rule.maxResponseBytes],
    ["timeoutMs", rule.timeoutMs],
  ]);
}

function requireString(value: JsonObject, name: string): string {
  const child = read(value, name);
  if (typeof child !== "string") {
    authorityFail("invalid_https_shape");
  }
  return child;
}

function rejectUnknown(value: JsonObject, allowed: string[]): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      authorityFail("unknown_field");
    }
  }
}

function read(value: JsonObject, key: string): HostJson | undefined {
  if (!Object.hasOwn(value, key)) {
    return undefined;
  }
  return value[key];
}

function readDomain(value: JsonObject | undefined, key: string): HostJson | undefined {
  if (value === undefined) {
    return undefined;
  }
  return read(value, key);
}

function emptyScope(): Scope {
  return { kind: "ids", ids: [] };
}

function isMethod(value: string): value is Method {
  for (const name of METHOD_NAMES) {
    if (name === value) {
      return true;
    }
  }
  return false;
}

function isAscii(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 0x7f) {
      return false;
    }
  }
  return true;
}

function isAlphabetic(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    const lower = unit >= 0x61 && unit <= 0x7a;
    const upper = unit >= 0x41 && unit <= 0x5a;
    if (!lower && !upper) {
      return false;
    }
  }
  return value.length > 0;
}

function isLdh(value: string): boolean {
  if (value.length === 0 || value.startsWith("-") || value.endsWith("-")) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    const digit = unit >= 0x30 && unit <= 0x39;
    const lower = unit >= 0x61 && unit <= 0x7a;
    const upper = unit >= 0x41 && unit <= 0x5a;
    if (!digit && !lower && !upper && unit !== 0x2d) {
      return false;
    }
  }
  return true;
}

function compareUtf16(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function authorityFail(code: AuthorityCode): never {
  const err = new TypeError(code);
  Reflect.set(err, "code", code);
  throw err;
}
