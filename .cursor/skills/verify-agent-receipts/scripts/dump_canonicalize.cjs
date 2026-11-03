"use strict";

const path = require("node:path");
const { canonicalize_bytes } = require(path.resolve(process.argv[2]));

const chunks = [];
process.stdin.on("data", (chunk) => {
  chunks.push(chunk);
});
process.stdin.on("end", () => {
  const input = Buffer.concat(chunks);
  try {
    const output = canonicalize_bytes(input);
    process.stdout.write(`ok ${output.toString("hex")}\n`);
  } catch (err) {
    const code = err && err.code ? String(err.code) : "unknown";
    process.stdout.write(`err ${code}\n`);
  }
});
