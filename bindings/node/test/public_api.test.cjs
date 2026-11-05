const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const api = require("..");

const SIGNATURES = {
  auditSigningKey: ["key"],
  canonicalJson: ["value"],
  compareAuthorityContracts: ["previous", "next"],
  controlledSigningKey: ["key"],
  isHttpsAuthoritySubset: ["inner", "outer"],
  normalizeAuthorityPolicy: ["value"],
  normalizeHttpsAuthorityRules: ["value"],
  resignAuditReceipt: ["receipt", "key"],
  signControlledIntegrity: ["value", "key", "keyId"],
  stableHash: ["value"],
  verifyAuditReceipt: ["receipt", "key"],
  verifyControlledIntegrity: ["value", "key", "keyId", "evidence"],
};

const CONSTANTS = [
  "AUDIT_RECEIPT_VERSION",
  "AUDIT_RECEIPT_V2_VERSION",
  "CONTROLLED_INTEGRITY_VERSION",
];

const RUST_ONLY_SIGNER_CODES = [
  "short_audit_key",
  "short_controlled_key",
  "invalid_key_id",
];

test("exported names", () => {
  assert.deepEqual(
    Object.keys(api).sort(),
    Object.keys(SIGNATURES).concat(CONSTANTS).sort(),
  );
});

test("declare parameter names", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "index.d.ts"), "utf8");
  pinParameters(readDeclareParams(source), SIGNATURES);
});

test("compare and normalize results are frozen", () => {
  const previous = { filesystem: { read: ["a"] } };
  const next = { filesystem: { read: ["a", "b"] } };
  const compared = api.compareAuthorityContracts(previous, next);
  pinCompareKeys(compared);
  assertDeepFrozen(compared, "compare");
  assertDeepFrozen(api.normalizeAuthorityPolicy(previous), "normalizeAuthorityPolicy");
  assertDeepFrozen(
    api.normalizeHttpsAuthorityRules([httpsRule()]),
    "normalizeHttpsAuthorityRules",
  );
});

test("canonicalize error codes", () => {
  const loop = {};
  loop.self = loop;
  observeCode("type_error", undefined, () => api.canonicalJson(undefined));
  observeCode("type_error", undefined, () => api.canonicalJson(Buffer.from("hi")));
  observeCode("too_deep", undefined, () => api.canonicalJson(nestedArrays(129)));
  observeCode("cycle", undefined, () => api.canonicalJson(loop));
});

test("authority error codes", () => {
  const cases = [
    ["not_an_object", () => api.compareAuthorityContracts([], {})],
    ["cross_version", () => api.compareAuthorityContracts({}, { version: "2" })],
    [
      "unsupported_version",
      () => api.compareAuthorityContracts({ version: "3" }, { version: "3" }),
    ],
    [
      "unknown_field",
      () =>
        api.compareAuthorityContracts(
          { filesystem: { read: [] } },
          { filesystem: { read: [], exec: ["x"] } },
        ),
    ],
    ["https_in_v1", () => api.compareAuthorityContracts({}, { network: { https: [] } })],
    [
      "outbound_in_v2",
      () =>
        api.compareAuthorityContracts(
          { version: "2" },
          { version: "2", network: { outbound: "any" } },
        ),
    ],
    [
      "invalid_scope",
      () => api.compareAuthorityContracts({ git: { write: [" padded"] } }, {}),
    ],
    [
      "invalid_flag",
      () => api.compareAuthorityContracts({ output: { unrestricted: "yes" } }, {}),
    ],
    [
      "invalid_https_host",
      () => api.compareAuthorityContracts(v2Https(httpsRule({ host: "127.0.0.1" })), { version: "2" }),
    ],
    [
      "invalid_https_port",
      () => api.compareAuthorityContracts(v2Https(httpsRule({ port: 0 })), { version: "2" }),
    ],
    [
      "invalid_https_method",
      () => api.compareAuthorityContracts(v2Https(httpsRule({ methods: ["get"] })), { version: "2" }),
    ],
    [
      "invalid_https_bounds",
      () =>
        api.compareAuthorityContracts(v2Https(httpsRule({ maxResponseBytes: 0 })), { version: "2" }),
    ],
    [
      "invalid_https_shape",
      () =>
        api.compareAuthorityContracts(
          { version: "2", network: { https: false } },
          { version: "2" },
        ),
    ],
  ];
  for (const [code, call] of cases) {
    observeCode(code, TypeError, call);
  }
});

test("host conversion type_error is an Error code", () => {
  observeCode("type_error", TypeError, () => api.compareAuthorityContracts(new Date(), {}));
});

test("signer errors keep napi status codes", () => {
  pinSigner(
    () => api.auditSigningKey("short"),
    "TypeError",
    "audit signingKey must contain at least 16 bytes",
  );
  pinSigner(
    () => api.controlledSigningKey("a".repeat(15)),
    "RangeError",
    "controlled integrity signing key must contain at least 16 bytes",
  );
  pinSigner(
    () => api.signControlledIntegrity({}, "0123456789abcdef", ""),
    "TypeError",
    "invalid key id",
  );
});

function pinParameters(parsed, expected) {
  assert.deepEqual(Object.keys(parsed).sort(), Object.keys(expected).sort());
  for (const name of Object.keys(expected)) {
    const params = parsed[name];
    assert.deepEqual(
      params.map((param) => param.name),
      expected[name],
    );
    for (const param of params) {
      assert.equal(param.optional, false, `${name} ${param.name}`);
    }
  }
}

function readDeclareParams(source) {
  if (typeof source !== "string" || source.length === 0) {
    throw new Error("missing declare file");
  }
  const parsed = {};
  for (const line of source.split("\n")) {
    const text = line.trim();
    if (text === "" || text.startsWith("/*") || text.startsWith("export const ")) {
      continue;
    }
    const match = text.match(/^export declare function (\w+)\((.*)\)(?::.*)?$/);
    if (!match) {
      throw new Error(`unrecognized declare line ${text}`);
    }
    const name = match[1];
    if (Object.hasOwn(parsed, name)) {
      throw new Error(`duplicate declare function ${name}`);
    }
    parsed[name] = splitDeclareParams(match[2]).map(readDeclareParam);
  }
  if (Object.keys(parsed).length === 0) {
    throw new Error("declare file has no functions");
  }
  return parsed;
}

function splitDeclareParams(inner) {
  if (inner.trim() === "") {
    return [];
  }
  const parts = [];
  let depth = 0;
  let current = "";
  for (const ch of inner) {
    if (ch === "<") {
      depth += 1;
    } else if (ch === ">") {
      if (depth === 0) {
        throw new Error("declare parameter has an unbalanced >");
      }
      depth -= 1;
    } else if (ch === "," && depth === 0) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (depth !== 0) {
    throw new Error("declare parameter has an unbalanced <");
  }
  parts.push(current);
  return parts;
}

function readDeclareParam(token) {
  const text = token.trim();
  if (text.includes("<") && text.includes(",")) {
    throw new Error(`declare parameter has a nested comma ${text}`);
  }
  const optional = text.match(/^(\w+)\?:/);
  if (optional) {
    return { name: optional[1], optional: true };
  }
  const required = text.match(/^(\w+):/);
  if (required) {
    return { name: required[1], optional: false };
  }
  throw new Error(`unrecognized declare parameter ${text}`);
}

function assertDeepFrozen(value, where) {
  if (value === null || typeof value !== "object") {
    return;
  }
  assert.equal(Object.isFrozen(value), true, where);
  const children = Object.values(value);
  for (let index = 0; index < children.length; index += 1) {
    assertDeepFrozen(children[index], `${where}[${index}]`);
  }
}

function pinCompareKeys(got) {
  assert.deepEqual(Object.keys(got).sort(), ["narrowed", "relationship", "widened"]);
  assert.equal(Array.isArray(got.widened), true);
  assert.equal(Array.isArray(got.narrowed), true);
}

function observeCode(code, ctor, call) {
  assert.throws(
    call,
    (err) => {
      if (typeof ctor === "function") {
        assert.equal(err instanceof ctor, true, err && err.name);
      }
      assert.equal(err.code, code, err && err.message);
      return true;
    },
  );
}

function pinSigner(call, status, message) {
  assert.throws(
    call,
    (err) => {
      assert.equal(err.message, message);
      assert.equal(err.code, status);
      for (const rustCode of RUST_ONLY_SIGNER_CODES) {
        assert.notEqual(err.code, rustCode);
      }
      return true;
    },
  );
}

function nestedArrays(depth) {
  let value = null;
  for (let index = 0; index < depth; index += 1) {
    value = [value];
  }
  return value;
}

function httpsRule(overrides) {
  return {
    protocol: "https",
    host: "api.example.com",
    port: 443,
    methods: ["GET"],
    resolution: "public-only",
    redirects: "none",
    maxResponseBytes: 1024,
    timeoutMs: 1000,
    ...overrides,
  };
}

function v2Https(rule) {
  return { version: "2", network: { https: [rule] } };
}
