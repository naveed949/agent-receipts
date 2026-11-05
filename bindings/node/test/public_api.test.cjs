const assert = require("node:assert/strict");
const test = require("node:test");

const api = require("..");

const FUNCTIONS = [
  "auditSigningKey",
  "canonicalJson",
  "compareAuthorityContracts",
  "controlledSigningKey",
  "isHttpsAuthoritySubset",
  "normalizeAuthorityPolicy",
  "normalizeHttpsAuthorityRules",
  "resignAuditReceipt",
  "signControlledIntegrity",
  "stableHash",
  "verifyAuditReceipt",
  "verifyControlledIntegrity",
];

const CONSTANTS = [
  "AUDIT_RECEIPT_VERSION",
  "AUDIT_RECEIPT_V2_VERSION",
  "CONTROLLED_INTEGRITY_VERSION",
];

const ERROR_CODES = [
  "not_utf8",
  "invalid_json",
  "too_deep",
  "cycle",
  "type_error",
];

test("exported names", () => {
  assert.deepEqual(Object.keys(api).sort(), FUNCTIONS.concat(CONSTANTS).sort());
});

test("canonicalize error.code is a documented Error code", () => {
  assert.throws(
    () => api.canonicalJson(undefined),
    (err) => {
      assert.equal(typeof err.code, "string");
      assert.ok(ERROR_CODES.includes(err.code), err.code);
      assert.equal(err.code, "type_error");
      return true;
    },
  );
});

test("authority TypeError.code is a documented AuthorityError code", () => {
  assert.throws(
    () => api.compareAuthorityContracts(new Date(), {}),
    (err) => {
      assert.equal(err.name, "TypeError");
      assert.equal(err.code, "type_error");
      return true;
    },
  );
});
