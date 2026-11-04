"use strict";

const fs = require("node:fs");
const path = require("node:path");

const { canonicalJson, stableHash } = require(path.resolve(process.argv[2]));

const text = fs.readFileSync(0, "utf8");
let value;
try {
  value = decode(JSON.parse(text));
} catch (err) {
  process.stderr.write(`parse ${err.message}\n`);
  process.exit(1);
}

try {
  const output = canonicalJson(value);
  const digest = stableHash(value);
  const hex = Buffer.from(output, "utf8").toString("hex");
  process.stdout.write(`ok ${hex} ${digest}\n`);
} catch (err) {
  const code = err && err.code ? String(err.code) : "unknown";
  process.stdout.write(`err ${code}\n`);
}

function decode(input) {
  if (Array.isArray(input)) {
    return input.map((item) => decode(item));
  }
  if (input && typeof input === "object") {
    const keys = Object.keys(input);
    if (keys.length === 1 && Object.prototype.hasOwnProperty.call(input, "$js")) {
      return decodeTag(input.$js);
    }
    const out = {};
    for (const key of keys) {
      out[key] = decode(input[key]);
    }
    return out;
  }
  return input;
}

function decodeTag(text) {
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

function parseNumber(token) {
  if (token === "" || /\s/.test(token) || !/^[-0-9]/.test(token)) {
    throw new Error(`unknown tag number:${token}`);
  }
  const value = JSON.parse(token);
  if (typeof value !== "number") {
    throw new Error(`unknown tag number:${token}`);
  }
  return value;
}
