"use strict";

const fs = require("node:fs");
const path = require("node:path");

const binding = require(path.resolve(process.argv[2]));
const { compareAuthorityContracts } = binding;

class DuplicateKey extends Error {}

const text = fs.readFileSync(0, "utf8");
let cmd;
try {
  cmd = parseCommand(text);
} catch (err) {
  if (err instanceof DuplicateKey) {
    process.stdout.write("err invalid_input\n");
    process.exit(0);
  }
  process.stdout.write(`err parse ${err && err.message ? err.message : err}\n`);
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

function parseCommand(source) {
  const parser = { source, i: 0 };
  skipWs(parser);
  const value = parseValue(parser);
  skipWs(parser);
  if (parser.i !== source.length) {
    throw new Error("trailing");
  }
  return value;
}

function parseValue(parser) {
  skipWs(parser);
  const ch = peek(parser);
  if (ch === "{") {
    return parseObject(parser);
  }
  if (ch === "[") {
    return parseArray(parser);
  }
  if (ch === '"') {
    return parseString(parser);
  }
  if (ch === "t") {
    return parseLiteral(parser, "true", true);
  }
  if (ch === "f") {
    return parseLiteral(parser, "false", false);
  }
  if (ch === "n") {
    return parseLiteral(parser, "null", null);
  }
  if (ch === "-" || (ch >= "0" && ch <= "9")) {
    return parseNumber(parser);
  }
  throw new Error("value");
}

function parseObject(parser) {
  eat(parser, "{");
  const out = {};
  const keys = new Set();
  skipWs(parser);
  if (peek(parser) === "}") {
    parser.i += 1;
    return out;
  }
  while (true) {
    skipWs(parser);
    if (peek(parser) !== '"') {
      throw new Error("key");
    }
    const key = parseString(parser);
    if (keys.has(key)) {
      throw new DuplicateKey(key);
    }
    keys.add(key);
    skipWs(parser);
    eat(parser, ":");
    out[key] = parseValue(parser);
    skipWs(parser);
    const next = peek(parser);
    if (next === ",") {
      parser.i += 1;
      continue;
    }
    if (next === "}") {
      parser.i += 1;
      return out;
    }
    throw new Error("object");
  }
}

function parseArray(parser) {
  eat(parser, "[");
  const out = [];
  skipWs(parser);
  if (peek(parser) === "]") {
    parser.i += 1;
    return out;
  }
  while (true) {
    out.push(parseValue(parser));
    skipWs(parser);
    const next = peek(parser);
    if (next === ",") {
      parser.i += 1;
      continue;
    }
    if (next === "]") {
      parser.i += 1;
      return out;
    }
    throw new Error("array");
  }
}

function parseString(parser) {
  eat(parser, '"');
  let out = "";
  while (true) {
    const ch = peek(parser);
    if (ch === undefined) {
      throw new Error("unterminated string");
    }
    parser.i += 1;
    if (ch === '"') {
      return out;
    }
    if (ch === "\\") {
      out += parseEscape(parser);
      continue;
    }
    if (ch.charCodeAt(0) < 0x20) {
      throw new Error("control");
    }
    out += ch;
  }
}

function parseEscape(parser) {
  const ch = peek(parser);
  parser.i += 1;
  switch (ch) {
    case '"':
    case "\\":
    case "/":
      return ch;
    case "b":
      return "\b";
    case "f":
      return "\f";
    case "n":
      return "\n";
    case "r":
      return "\r";
    case "t":
      return "\t";
    case "u": {
      let code = 0;
      for (let n = 0; n < 4; n += 1) {
        const hex = peek(parser);
        parser.i += 1;
        const digit = hexValue(hex);
        if (digit < 0) {
          throw new Error("hex");
        }
        code = (code << 4) | digit;
      }
      return String.fromCharCode(code);
    }
    default:
      throw new Error("escape");
  }
}

function hexValue(ch) {
  if (ch >= "0" && ch <= "9") {
    return ch.charCodeAt(0) - 48;
  }
  if (ch >= "a" && ch <= "f") {
    return ch.charCodeAt(0) - 87;
  }
  if (ch >= "A" && ch <= "F") {
    return ch.charCodeAt(0) - 55;
  }
  return -1;
}

function parseNumber(parser) {
  const start = parser.i;
  if (peek(parser) === "-") {
    parser.i += 1;
  }
  if (peek(parser) === "0") {
    parser.i += 1;
  } else if (peek(parser) >= "1" && peek(parser) <= "9") {
    parser.i += 1;
    while (peek(parser) >= "0" && peek(parser) <= "9") {
      parser.i += 1;
    }
  } else {
    throw new Error("number");
  }
  if (peek(parser) === ".") {
    parser.i += 1;
    if (!(peek(parser) >= "0" && peek(parser) <= "9")) {
      throw new Error("fraction");
    }
    while (peek(parser) >= "0" && peek(parser) <= "9") {
      parser.i += 1;
    }
  }
  if (peek(parser) === "e" || peek(parser) === "E") {
    parser.i += 1;
    if (peek(parser) === "+" || peek(parser) === "-") {
      parser.i += 1;
    }
    if (!(peek(parser) >= "0" && peek(parser) <= "9")) {
      throw new Error("exponent");
    }
    while (peek(parser) >= "0" && peek(parser) <= "9") {
      parser.i += 1;
    }
  }
  return JSON.parse(parser.source.slice(start, parser.i));
}

function parseLiteral(parser, lit, value) {
  if (parser.source.slice(parser.i, parser.i + lit.length) !== lit) {
    throw new Error("literal");
  }
  parser.i += lit.length;
  return value;
}

function peek(parser) {
  return parser.source[parser.i];
}

function eat(parser, want) {
  if (peek(parser) !== want) {
    throw new Error("token");
  }
  parser.i += 1;
}

function skipWs(parser) {
  while (
    peek(parser) === " " ||
    peek(parser) === "\t" ||
    peek(parser) === "\n" ||
    peek(parser) === "\r"
  ) {
    parser.i += 1;
  }
}
