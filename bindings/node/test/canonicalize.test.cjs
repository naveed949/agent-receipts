const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { canonicalJson, stableHash } = require("..");

const referenceDir = path.join(__dirname, "..", "..", "..", "vectors", "reference");

test("reference vectors", () => {
  const root = loadReference();
  const allow = readAllowlist(path.join(referenceDir, "pending-kinds.txt"));
  const rows = root.vectors;
  assert.equal(root.count, rows.length);
  assert.equal(rows.length, 20);
  const pendingLines = [];
  const seen = [];
  let canonicalOk = 0;
  const failures = [];
  for (const row of rows) {
    const name = requireString(row, "name", failures);
    const kind = requireString(row, "kind", failures);
    if (name === null || kind === null) {
      continue;
    }
    if (kind === "canonicalize") {
      try {
        checkCanonicalize(row, name);
        canonicalOk += 1;
      } catch (err) {
        failures.push(`${name} ${err.message}`);
      }
      continue;
    }
    if (!allow.includes(kind)) {
      failures.push(`unknown kind ${kind}`);
      continue;
    }
    if (!seen.includes(kind)) {
      seen.push(kind);
    }
    pendingLines.push(`pending ${kind} ${name}`);
  }
  for (const kind of allow) {
    if (!seen.includes(kind)) {
      failures.push(`unused pending kind ${kind}`);
    }
  }
  if (canonicalOk !== 8 || pendingLines.length !== 12 || canonicalOk + pendingLines.length !== 20) {
    failures.push(`counts canonicalize ${canonicalOk} pending ${pendingLines.length}`);
  }
  for (const line of pendingLines) {
    console.log(line);
  }
  console.log(`pending ${pendingLines.length}`);
  console.log(`canonicalize ${canonicalOk} ok`);
  assert.deepEqual(failures, []);
});

test("usage object", () => {
  const value = {
    b: 1,
    a: { d: [3, { z: true, y: null }], c: "x" },
    B: 2,
    _: 0,
  };
  assert.equal(
    canonicalJson(value),
    '{"B":2,"_":0,"a":{"c":"x","d":[3,{"y":null,"z":true}]},"b":1}',
  );
  assert.equal(
    stableHash(value),
    "5588b64560343c75cefb360b90918927a446fa3131288ef20c4ec67aaf4381f0",
  );
  assert.equal(typeof canonicalJson(value), "string");
  assert.equal(typeof stableHash(value), "string");
});

test("host scalars and containers", () => {
  assert.equal(canonicalJson(null), "null");
  assert.equal(canonicalJson(true), "true");
  assert.equal(canonicalJson(false), "false");
  assert.equal(canonicalJson(1), "1");
  assert.equal(canonicalJson("hello"), '"hello"');
  assert.equal(canonicalJson([]), "[]");
  assert.equal(canonicalJson({}), "{}");
  assert.equal(canonicalJson([1, 2, 3]), "[1,2,3]");
  const bare = Object.create(null);
  bare.b = 1;
  bare.a = 2;
  assert.equal(canonicalJson(bare), '{"a":2,"b":1}');
});

test("lone surrogate and negative zero", () => {
  assert.equal(Object.is(-0, 0), false);
  assert.equal(canonicalJson(-0), "0");
  assert.equal(canonicalJson(0), "0");
  const surrogate = canonicalJson("\ud800");
  assert.equal(surrogate, '"\\ud800"');
  assert.equal(stableHash("\ud800").length, 64);
});

test("host rejects", () => {
  assertCode(undefined, "type_error");
  assertCode({ present: 1, missing: undefined }, "type_error");
  assertCode([1, undefined], "type_error");
  assertCode(NaN, "type_error");
  assertCode(Infinity, "type_error");
  assertCode(-Infinity, "type_error");
  assertCode(1n, "type_error");
  assertCode(9007199254740993n, "type_error");
  assertCode(Symbol("s"), "type_error");
  assertCode(() => 1, "type_error");
  assertCode(new Date(), "type_error");
  assertCode(new Map(), "type_error");
  assertCode(new Set(), "type_error");
  assertCode(Buffer.from("[]"), "type_error");
  assertCode(new Uint8Array([1, 2, 3]), "type_error");
  assertCode(new ArrayBuffer(4), "type_error");
  assertCode(new DataView(new ArrayBuffer(4)), "type_error");
  class Box {
    constructor() {
      this.a = 1;
    }
  }
  assertCode(new Box(), "type_error");
  class Row extends Array {}
  const row = new Row();
  row.push(1);
  assertCode(row, "type_error");
  const hole = [1, 2, 3];
  delete hole[1];
  assertCode(hole, "type_error");
  assertCode([1, , 2], "type_error");
  const extra = [1, 2];
  extra.extra = true;
  assertCode(extra, "type_error");
  const hidden = {};
  Object.defineProperty(hidden, "a", {
    value: 1,
    enumerable: false,
    configurable: true,
    writable: true,
  });
  assertCode(hidden, "type_error");
  const keyed = { a: 1 };
  keyed[Symbol("s")] = 2;
  assertCode(keyed, "type_error");
  const sparse = [];
  sparse.length = 1000000;
  assertCode(sparse, "type_error");
});

test("every proxy is type_error", () => {
  class Box {
    constructor() {
      this.a = 1;
    }
  }
  const targets = [
    Buffer.from([1, 2, 3]),
    new Uint8Array([1, 2, 3]),
    new Date(),
    new Map(),
    new Set(),
    new Box(),
    new DataView(new ArrayBuffer(4)),
    new ArrayBuffer(4),
    { a: 1 },
    [1, 2, 3],
  ];
  for (const target of targets) {
    assertCode(new Proxy(target, {}), "type_error");
  }
});

test("a throwing getter is left alone", () => {
  const boom = {};
  Object.defineProperty(boom, "a", {
    enumerable: true,
    get() {
      throw new Error("boom");
    },
  });
  assert.throws(
    () => canonicalJson(boom),
    (err) => {
      assert.equal(err.message, "boom");
      assert.notEqual(err.code, "type_error");
      return true;
    },
  );
});

test("cycles depth and shared values", () => {
  const loop = [];
  loop.push(loop);
  assertCode(loop, "cycle");
  const obj = {};
  obj.self = obj;
  assertCode(obj, "cycle");
  const shared = { k: 1 };
  assert.equal(canonicalJson({ a: shared, b: shared }), '{"a":{"k":1},"b":{"k":1}}');
  assert.equal(canonicalJson(nest(128)), `${"[".repeat(128)}null${"]".repeat(128)}`);
  assertCode(nest(129), "too_deep");
  class Box {
    constructor() {
      this.a = 1;
    }
  }
  assertCode(nestLeaf(128, new Date()), "type_error");
  assertCode(nestLeaf(128, new Map()), "type_error");
  assertCode(nestLeaf(128, Buffer.from("x")), "type_error");
  assertCode(nestLeaf(128, new Box()), "type_error");
  assert.equal(canonicalJson(nestLeaf(128, "hi")), `${"[".repeat(128)}"hi"${"]".repeat(128)}`);
  assert.equal(canonicalJson(nestObjects(128)), `${'{"k":'.repeat(127)}{}${"}".repeat(127)}`);
  assertCode(nestObjects(129), "too_deep");
  assertCode(nestLeaf(128, {}), "too_deep");
});

function loadReference() {
  const text = fs.readFileSync(path.join(referenceDir, "vectors.json"), "utf8");
  assert.notEqual(text, "");
  const root = JSON.parse(text);
  assert.equal(typeof root, "object");
  assert.ok(root);
  assert.ok(Array.isArray(root.vectors));
  return root;
}

function readAllowlist(file) {
  const lines = [];
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "") {
      continue;
    }
    assert.notEqual(line, "canonicalize");
    assert.equal(lines.includes(line), false);
    lines.push(line);
  }
  return lines;
}

function requireString(row, field, failures) {
  const value = row[field];
  if (typeof value !== "string") {
    failures.push(`missing ${field}`);
    return null;
  }
  return value;
}

function checkCanonicalize(row, name) {
  const hasExpected = Object.prototype.hasOwnProperty.call(row, "expected");
  const hasError = Object.prototype.hasOwnProperty.call(row, "expectedError");
  if (hasExpected === hasError) {
    throw new Error("needs expected or expectedError");
  }
  if (hasExpected) {
    checkSuccess(row.input, row.expected, name);
    return;
  }
  checkRejections(row.input, row.expectedError, name);
}

function checkSuccess(value, expected, name) {
  const decoded = decode(value);
  const text = canonicalJson(decoded);
  const digest = stableHash(decoded);
  assert.equal(typeof text, "string");
  assert.equal(typeof digest, "string");
  const gotHex = Buffer.from(text, "utf8").toString("hex");
  assert.equal(gotHex, expected.canonicalUtf8Hex, name);
  assert.equal(digest, expected.stableHash, name);
  assert.equal(canonicalJson(decoded), text, name);
  assert.equal(stableHash(decoded), digest, name);
}

function checkRejections(value, expectedError, name) {
  if (!value || typeof value !== "object" || !value.cases) {
    throw new Error(`${name} has no cases`);
  }
  const cases = value.cases;
  const caseKeys = Object.keys(cases).sort();
  const errorKeys = Object.keys(expectedError).sort();
  assert.deepEqual(caseKeys, errorKeys, name);
  assert.ok(caseKeys.length > 0, name);
  for (const label of caseKeys) {
    const spec = expectedError[label];
    assert.equal(spec.type, "TypeError", `${name} ${label}`);
    assertCode(decode(cases[label]), "type_error");
  }
}

function decode(value) {
  if (Array.isArray(value)) {
    return value.map((item) => decode(item));
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 1 && Object.prototype.hasOwnProperty.call(value, "$js")) {
      return decodeTag(value.$js);
    }
    const out = {};
    for (const key of keys) {
      out[key] = decode(value[key]);
    }
    return out;
  }
  return value;
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

function assertCode(value, code) {
  assert.throws(
    () => canonicalJson(value),
    (err) => {
      assert.equal(err.code, code);
      assert.equal(err.message, code);
      return true;
    },
  );
  assert.throws(
    () => stableHash(value),
    (err) => {
      assert.equal(err.code, code);
      return true;
    },
  );
}

function nest(depth) {
  return nestLeaf(depth, null);
}

function nestLeaf(depth, leaf) {
  let value = leaf;
  for (let index = 0; index < depth; index += 1) {
    value = [value];
  }
  return value;
}

function nestObjects(depth) {
  let value = {};
  for (let index = 1; index < depth; index += 1) {
    value = { k: value };
  }
  return value;
}
