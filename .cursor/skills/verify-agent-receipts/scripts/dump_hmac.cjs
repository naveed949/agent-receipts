"use strict";

const fs = require("node:fs");
const path = require("node:path");

const binding = require(path.resolve(process.argv[2]));
const {
  auditSigningKey,
  canonicalJson,
  controlledSigningKey,
  resignAuditReceipt,
  signControlledIntegrity,
  stableHash,
  verifyAuditReceipt,
  verifyControlledIntegrity,
} = binding;

const text = fs.readFileSync(0, "utf8");
let cmd;
try {
  cmd = JSON.parse(text);
} catch (err) {
  process.stdout.write(`err parse ${err.message}\n`);
  process.exit(0);
}

try {
  process.stdout.write(`${dispatch(cmd)}\n`);
} catch (err) {
  const message = err && err.message ? String(err.message) : "unknown";
  process.stdout.write(`err ${message}\n`);
}

function dispatch(cmd) {
  switch (cmd.op) {
    case "verify_audit":
      return `ok ${verifyAuditReceipt(cmd.receipt, keyValue(cmd))}`;
    case "resign":
      return `ok ${canonicalJson(resignAuditReceipt(cmd.receipt, keyValue(cmd)))}`;
    case "resign_then_verify": {
      const resigned = resignAuditReceipt(cmd.receipt, keyValue(cmd));
      return `ok ${verifyAuditReceipt(resigned, keyValue(cmd))}`;
    }
    case "verify_controlled":
      return `ok ${verifyControlledIntegrity(
        cmd.value,
        keyValue(cmd),
        cmd.keyId,
        cmd.evidence,
      )}`;
    case "sign_controlled":
      return `ok ${canonicalJson(signControlledIntegrity(cmd.value, keyValue(cmd), cmd.keyId))}`;
    case "audit_signing_key":
      auditSigningKey(keyValue(cmd));
      return "ok";
    case "controlled_signing_key":
      controlledSigningKey(keyValue(cmd));
      return "ok";
    case "stable_hash":
      return `ok ${stableHash(cmd.value)}`;
    default:
      return `err unknown op ${cmd.op}`;
  }
}

function keyValue(cmd) {
  if (cmd.as === "bytes") {
    return Buffer.from(String(cmd.key), "utf8");
  }
  return cmd.key;
}
