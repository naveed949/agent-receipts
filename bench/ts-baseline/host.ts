import { createHash } from "node:crypto";
import { types } from "node:util";

const MAX_CONTAINER_DEPTH = 128;
const MAX_ARRAY_INDEX = 4294967294;

export type JsonObject = { [key: string]: HostJson };

export type HostJson = null | boolean | number | string | HostJson[] | JsonObject;

export function fail(code: "type_error" | "too_deep" | "cycle"): never {
  const err = new TypeError(code);
  Reflect.set(err, "code", code);
  throw err;
}

export function isRecord(value: HostJson): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function canonicalJson(value: unknown): string {
  return emit(copyHost(value));
}

export function stableHash(value: unknown): string {
  return hashTree(copyHost(value));
}

export function hashTree(value: HostJson): string {
  return createHash("sha256").update(canonicalBytes(value)).digest("hex");
}

export function canonicalBytes(value: HostJson): Buffer {
  return Buffer.from(emit(value), "utf8");
}

export function objectFrom(entries: Array<[string, HostJson]>): JsonObject {
  const out = blankObject();
  for (const [key, value] of entries) {
    define(out, key, value);
  }
  return out;
}

export function copyHost(value: unknown): HostJson {
  return copyValue(value, 0, []);
}

export function emit(value: HostJson): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    return emitNumber(value);
  }
  if (typeof value === "string") {
    return emitString(value);
  }
  if (Array.isArray(value)) {
    return emitArray(value);
  }
  return emitObject(value);
}

function copyValue(value: unknown, depth: number, ancestors: object[]): HostJson {
  if (value === null) {
    return null;
  }
  if (typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("type_error");
    }
    return value;
  }
  if (typeof value !== "object") {
    fail("type_error");
  }
  return copyObject(value, depth, ancestors);
}

function copyObject(value: object, depth: number, ancestors: object[]): HostJson {
  rejectExotic(value);
  if (Array.isArray(value)) {
    return copyArray(value, depth, ancestors);
  }
  return copyPlain(value, depth, ancestors);
}

function rejectExotic(value: object): void {
  if (types.isProxy(value)) {
    fail("type_error");
  }
  if (
    types.isTypedArray(value) ||
    types.isArrayBuffer(value) ||
    types.isSharedArrayBuffer(value) ||
    types.isDataView(value)
  ) {
    fail("type_error");
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    fail("type_error");
  }
}

function copyArray(value: unknown[], depth: number, ancestors: object[]): HostJson[] {
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    fail("type_error");
  }
  const indexes: string[] = [];
  let sawLength = false;
  for (const name of Object.getOwnPropertyNames(value)) {
    if (name === "length") {
      sawLength = true;
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (descriptor === undefined || !descriptor.enumerable) {
      fail("type_error");
    }
    indexes.push(name);
  }
  if (!sawLength || indexes.length !== value.length) {
    fail("type_error");
  }
  for (const name of indexes) {
    if (!isElementIndex(name, value.length)) {
      fail("type_error");
    }
  }
  enter(value, depth, ancestors);
  try {
    const items: HostJson[] = [];
    for (let index = 0; index < value.length; index += 1) {
      items.push(copyValue(value[index], depth + 1, ancestors));
    }
    return items;
  } finally {
    ancestors.pop();
  }
}

function copyPlain(value: object, depth: number, ancestors: object[]): JsonObject {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail("type_error");
  }
  const names = Object.getOwnPropertyNames(value);
  enter(value, depth, ancestors);
  try {
    const out = blankObject();
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (descriptor === undefined || !descriptor.enumerable) {
        fail("type_error");
      }
      define(out, name, copyValue(Reflect.get(value, name), depth + 1, ancestors));
    }
    return out;
  } finally {
    ancestors.pop();
  }
}

function enter(value: object, depth: number, ancestors: object[]): void {
  if (ancestors.includes(value)) {
    fail("cycle");
  }
  if (depth + 1 > MAX_CONTAINER_DEPTH) {
    fail("too_deep");
  }
  ancestors.push(value);
}

function isElementIndex(key: string, length: number): boolean {
  const index = arrayIndex(key);
  return index !== undefined && index < length;
}

function arrayIndex(key: string): number | undefined {
  if (key.length === 0 || key.length > 10) {
    return undefined;
  }
  if (key.length > 1 && key.charCodeAt(0) === 0x30) {
    return undefined;
  }
  let value = 0;
  for (let index = 0; index < key.length; index += 1) {
    const unit = key.charCodeAt(index);
    if (unit < 0x30 || unit > 0x39) {
      return undefined;
    }
    value = value * 10 + (unit - 0x30);
  }
  if (value > MAX_ARRAY_INDEX) {
    return undefined;
  }
  return value;
}

function emitNumber(value: number): string {
  if (!Number.isFinite(value)) {
    fail("type_error");
  }
  if (Object.is(value, -0)) {
    return "0";
  }
  return value.toString();
}

function emitArray(value: HostJson[]): string {
  const parts: string[] = [];
  for (const item of value) {
    parts.push(emit(item));
  }
  return `[${parts.join(",")}]`;
}

function emitObject(value: JsonObject): string {
  const keys = Object.keys(value).sort(compareKeys);
  const parts: string[] = [];
  for (const key of keys) {
    parts.push(`${emitString(key)}:${emit(value[key])}`);
  }
  return `{${parts.join(",")}}`;
}

function compareKeys(left: string, right: string): number {
  const leftIndex = arrayIndex(left);
  const rightIndex = arrayIndex(right);
  if (leftIndex !== undefined && rightIndex !== undefined) {
    return leftIndex - rightIndex;
  }
  if (leftIndex !== undefined) {
    return -1;
  }
  if (rightIndex !== undefined) {
    return 1;
  }
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function emitString(value: string): string {
  const parts: string[] = ['"'];
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit === 0x22) {
      parts.push('\\"');
      continue;
    }
    if (unit === 0x5c) {
      parts.push("\\\\");
      continue;
    }
    if (unit === 0x08) {
      parts.push("\\b");
      continue;
    }
    if (unit === 0x0c) {
      parts.push("\\f");
      continue;
    }
    if (unit === 0x0a) {
      parts.push("\\n");
      continue;
    }
    if (unit === 0x0d) {
      parts.push("\\r");
      continue;
    }
    if (unit === 0x09) {
      parts.push("\\t");
      continue;
    }
    if (unit < 0x20) {
      parts.push(hex4(unit));
      continue;
    }
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = index + 1 < value.length ? value.charCodeAt(index + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        parts.push(value.slice(index, index + 2));
        index += 1;
        continue;
      }
      parts.push(hex4(unit));
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) {
      parts.push(hex4(unit));
      continue;
    }
    parts.push(value.charAt(index));
  }
  parts.push('"');
  return parts.join("");
}

function hex4(unit: number): string {
  const hex = "0123456789abcdef";
  return `\\u${hex[(unit >> 12) & 0xf]}${hex[(unit >> 8) & 0xf]}${hex[(unit >> 4) & 0xf]}${hex[unit & 0xf]}`;
}

function blankObject(): JsonObject {
  const created: unknown = Object.create(null);
  if (!isEmptyRecord(created)) {
    throw new Error("object");
  }
  return created;
}

function isEmptyRecord(value: unknown): value is JsonObject {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === null &&
    Object.keys(value).length === 0
  );
}

function define(target: JsonObject, key: string, value: HostJson): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}
