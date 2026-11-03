const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { canonicalize_bytes } = require("..");

const dir = path.join(__dirname, "..", "..", "..", "vectors", "canonicalize");
const files = fs
  .readdirSync(dir)
  .filter((name) => name.endsWith(".json"))
  .sort();

test("vector directory is not empty", () => {
  assert.ok(files.length > 0, "vectors/canonicalize is empty");
});

for (const name of files) {
  test(name, () => {
    const data = JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
    const keys = Object.keys(data).sort();
    const raw = decodeField(data.input_b64);
    if (keys.length === 2 && keys[0] === "input_b64" && keys[1] === "output_b64") {
      const expected = decodeField(data.output_b64);
      const got = canonicalize_bytes(raw);
      assert.equal(Buffer.isBuffer(got), true);
      assert.equal(got.equals(expected), true);
      const again = canonicalize_bytes(got);
      assert.equal(Buffer.isBuffer(again), true);
      assert.equal(again.equals(got), true);
      return;
    }
    if (keys.length === 2 && keys[0] === "error" && keys[1] === "input_b64") {
      assert.throws(
        () => canonicalize_bytes(raw),
        (err) => {
          assert.equal(err.code, data.error);
          return true;
        },
      );
      return;
    }
    assert.fail(`illegal keys in ${name}: ${keys.join(", ")}`);
  });
}

function decodeField(field) {
  const buf = Buffer.from(field, "base64");
  assert.equal(buf.toString("base64"), field);
  return buf;
}
