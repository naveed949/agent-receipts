"use strict";

const fs = require("node:fs");
const path = require("node:path");

const binding = require(path.resolve(process.argv[2]));
const { compareAuthorityContracts } = binding;

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
  const isType = err instanceof TypeError;
  process.stdout.write(isType ? "err TypeError\n" : `err ${err && err.message ? err.message : "unknown"}\n`);
}

function dispatch(cmd) {
  const got = compareAuthorityContracts(cmd.previous, cmd.next);
  return `ok ${JSON.stringify({
    relationship: got.relationship,
    widened: got.widened,
    narrowed: got.narrowed,
  })}`;
}
