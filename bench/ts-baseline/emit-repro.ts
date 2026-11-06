import assert from "node:assert/strict";
import { canonicalJson } from "./index.ts";

const OBJECT_SEED = 0xa41c;
const TARGET_UTF8 = 524306;

const tree = objectTree(524288);
const text = canonicalJson(tree);
assert.equal(text, canonicalJson(tree));
assert.equal(Buffer.byteLength(text, "utf8"), TARGET_UTF8);
assert.equal(text, emitPerChar(tree));
assert.equal(emitStringBulk("plain"), emitStringPerChar("plain"));
assert.equal(emitStringBulk("a\"b\\c\n\r\t\b\f"), emitStringPerChar("a\"b\\c\n\r\t\b\f"));
assert.equal(emitStringBulk("\u0001\ud800\udfff\ud800x"), emitStringPerChar("\u0001\ud800\udfff\ud800x"));
assert.equal(emitStringBulk("😀"), emitStringPerChar("😀"));
console.log(`emit-repro ok utf8=${TARGET_UTF8}`);

function objectTree(budget: number): Record<string, unknown> {
  const rng = mulberry32(OBJECT_SEED);
  const root: Record<string, unknown> = {
    "2": "two",
    "10": "ten",
    nest: nest(4),
    mix: [seededString(rng, 4), 1, null],
  };
  let guard = 0;
  while (Buffer.byteLength(canonicalJson(root), "utf8") < budget) {
    const deficit = budget - Buffer.byteLength(canonicalJson(root), "utf8");
    const count = deficit > 256 ? Math.min(400, Math.max(1, Math.floor(deficit / 40))) : 1;
    const width = deficit > 256 ? 8 : deficit + 8;
    for (let index = 0; index < count; index += 1) {
      root[`f${Object.keys(root).length.toString(36)}`] = seededString(rng, width);
    }
    guard += 1;
    if (guard > 80) {
      throw new Error("object tree did not reach size");
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

function emitPerChar(value: unknown): string {
  return emitValue(value, emitStringPerChar);
}

function emitValue(value: unknown, emitStr: (text: string) => string): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      return "0";
    }
    return value.toString();
  }
  if (typeof value === "string") {
    return emitStr(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => emitValue(item, emitStr)).join(",")}]`;
  }
  if (typeof value !== "object") {
    throw new Error("emit");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort(compareKeys);
  return `{${keys.map((key) => `${emitStr(key)}:${emitValue(record[key], emitStr)}`).join(",")}}`;
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
  if (value > 4294967294) {
    return undefined;
  }
  return value;
}

function hex4(unit: number): string {
  const hex = "0123456789abcdef";
  return `\\u${hex[(unit >> 12) & 0xf]}${hex[(unit >> 8) & 0xf]}${hex[(unit >> 4) & 0xf]}${hex[unit & 0xf]}`;
}

function emitStringPerChar(value: string): string {
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

function emitStringBulk(value: string): string {
  const parts: string[] = ['"'];
  let run = 0;
  const flush = (end: number) => {
    if (end > run) {
      parts.push(value.slice(run, end));
    }
  };
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    let escaped: string | undefined;
    if (unit === 0x22) {
      escaped = '\\"';
    } else if (unit === 0x5c) {
      escaped = "\\\\";
    } else if (unit === 0x08) {
      escaped = "\\b";
    } else if (unit === 0x0c) {
      escaped = "\\f";
    } else if (unit === 0x0a) {
      escaped = "\\n";
    } else if (unit === 0x0d) {
      escaped = "\\r";
    } else if (unit === 0x09) {
      escaped = "\\t";
    } else if (unit < 0x20) {
      escaped = hex4(unit);
    } else if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = index + 1 < value.length ? value.charCodeAt(index + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        index += 1;
        continue;
      }
      escaped = hex4(unit);
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      escaped = hex4(unit);
    }
    if (escaped !== undefined) {
      flush(index);
      parts.push(escaped);
      run = index + 1;
    }
  }
  flush(value.length);
  parts.push('"');
  return parts.join("");
}
