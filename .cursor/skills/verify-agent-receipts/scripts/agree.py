#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path


class Missing:
    pass


class RejectedInteger:
    def __init__(self, digits: str) -> None:
        self.digits = digits


def decode_field(field: str) -> bytes:
    raw = base64.standard_b64decode(field)
    encoded = base64.standard_b64encode(raw).decode("ascii")
    if encoded != field:
        raise ValueError(f"base64 field {field} encodes as {encoded}")
    return raw


def read_allowlist(path: Path) -> list[str]:
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line == "":
            continue
        if line == "canonicalize":
            raise ValueError("allowlist contains canonicalize")
        if line in lines:
            raise ValueError(f"duplicate pending kind {line}")
        lines.append(line)
    return lines


def decode(value):
    if isinstance(value, dict):
        if len(value) == 1 and "$js" in value:
            return decode_tag(value["$js"])
        return {key: decode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [decode(item) for item in value]
    return value


def decode_tag(text):
    if type(text) is not str:
        raise ValueError("tag is not a string")
    if text == "-0":
        return -0.0
    if text == "NaN":
        return float("nan")
    if text == "Infinity":
        return float("inf")
    if text == "-Infinity":
        return float("-inf")
    if text == "undefined":
        return Missing()
    if text.startswith("bigint:"):
        digits = text[len("bigint:") :]
        if digits.isdigit():
            return RejectedInteger(digits)
        raise ValueError(f"unknown tag {text}")
    if text.startswith("number:"):
        return parse_number(text[len("number:") :])
    raise ValueError(f"unknown tag {text}")


def parse_number(token: str) -> float:
    if token == "" or any(char.isspace() for char in token):
        raise ValueError(f"unknown tag number:{token}")
    if not (token[0] == "-" or token[0].isdigit()):
        raise ValueError(f"unknown tag number:{token}")
    try:
        value = json.loads(token, parse_int=float, parse_float=float)
    except json.JSONDecodeError as err:
        raise ValueError(f"unknown tag number:{token}") from err
    if type(value) is not float:
        raise ValueError(f"unknown tag number:{token}")
    return value


def emit_json(value) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is float:
        return json.dumps(value)
    if type(value) is str:
        return json.dumps(value, ensure_ascii=True)
    if type(value) is list:
        return "[" + ",".join(emit_json(item) for item in value) + "]"
    if type(value) is dict:
        parts = []
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("object key is not a string")
            parts.append(json.dumps(key, ensure_ascii=True) + ":" + emit_json(item))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"cannot emit {type(value).__name__}")


def parse_dump(text: str) -> tuple[str, str, str | None]:
    line = text.strip()
    if line.startswith("ok "):
        hex_text, digest = line[3:].split()
        return ("ok", hex_text, digest)
    if line.startswith("err "):
        return ("err", line[4:].strip(), None)
    raise ValueError(f"dump output was not ok/err: {text!r}")


def run_dump(command: list[str], raw: bytes) -> tuple[str, str, str | None]:
    completed = subprocess.run(
        command,
        input=raw,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        err = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"{command[0]} exited {completed.returncode}: {err}")
    return parse_dump(completed.stdout.decode("utf-8"))


def python_value(value) -> tuple[str, str, str | None]:
    import agent_receipts

    try:
        text = agent_receipts.canonical_json(value)
        digest = agent_receipts.stable_hash(value)
    except agent_receipts.CanonicalizeError as err:
        return ("err", str(err.code), None)
    if type(text) is not str or type(digest) is not str:
        raise TypeError("Python results are not str")
    return ("ok", text.encode("utf-8").hex(), digest)


def python_bytes(raw: bytes) -> tuple[str, str, str | None]:
    return python_value(raw)


def load_reference(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if text == "":
        raise SystemExit(f"{path} is empty")
    root = json.loads(text, parse_int=float, parse_float=float)
    if not isinstance(root, dict) or not isinstance(root.get("vectors"), list):
        raise SystemExit(f"{path} is not a reference file")
    rows = root["vectors"]
    if root.get("count") != len(rows) or len(rows) != 20:
        raise SystemExit(f"count {root.get('count')} len {len(rows)}")
    return root


def check_reference(reference: Path, rust_cmd: list[str], node_cmd: list[str]) -> int:
    root = load_reference(reference / "vectors.json")
    allow = read_allowlist(reference / "pending-kinds.txt")
    pending_lines: list[str] = []
    seen: list[str] = []
    ok = 0
    failed = 0
    for row in root["vectors"]:
        name = row.get("name")
        kind = row.get("kind")
        if type(name) is not str or type(kind) is not str:
            failed += 1
            print("reference row missing name or kind", file=sys.stderr)
            continue
        if kind == "canonicalize":
            try:
                check_canonicalize_row(row, name, rust_cmd, node_cmd)
            except Exception as err:
                failed += 1
                print(f"reference {name} ... FAILED")
                print(f"  {err}", file=sys.stderr)
            else:
                ok += 1
            continue
        if kind not in allow:
            failed += 1
            print(f"unknown kind {kind}", file=sys.stderr)
            continue
        if kind not in seen:
            seen.append(kind)
        line = f"pending {kind} {name}"
        pending_lines.append(line)
        print(line)
    for kind in allow:
        if kind not in seen:
            failed += 1
            print(f"unused pending kind {kind}", file=sys.stderr)
    if ok != 8 or len(pending_lines) != 12 or ok + len(pending_lines) != 20:
        failed += 1
        print(
            f"counts canonicalize {ok} pending {len(pending_lines)}",
            file=sys.stderr,
        )
    print(f"pending {len(pending_lines)}")
    print(f"reference {ok} ok")
    return failed


def check_canonicalize_row(row, name: str, rust_cmd: list[str], node_cmd: list[str]) -> None:
    has_expected = "expected" in row
    has_error = "expectedError" in row
    if has_expected == has_error:
        raise ValueError("needs expected or expectedError")
    if has_expected:
        check_success(row["input"], row["expected"], name, rust_cmd, node_cmd)
        return
    check_rejections(row["input"], row["expectedError"], name, node_cmd)
    print(f"reference {name} python-node type_error")


def check_success(value, expected, name: str, rust_cmd: list[str], node_cmd: list[str]) -> None:
    decoded = decode(value)
    python = python_value(decoded)
    payload = emit_json(decoded).encode("utf-8")
    rust = run_dump(rust_cmd, payload)
    node = run_dump(node_cmd, payload)
    want = ("ok", expected["canonicalUtf8Hex"], expected["stableHash"])
    if python != want or rust != want or node != want:
        raise ValueError(f"rust={rust} python={python} node={node} want={want}")
    print(f"reference {name} rust-python-node ok")


def check_rejections(value, expected_error, name: str, node_cmd: list[str]) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("cases"), dict):
        raise ValueError(f"{name} has no cases")
    if not isinstance(expected_error, dict):
        raise ValueError(f"{name} rejection shape")
    cases = value["cases"]
    if not cases or set(cases) != set(expected_error):
        raise ValueError(f"{name} rejection keys")
    for label, child in cases.items():
        spec = expected_error[label]
        if not isinstance(spec, dict) or spec.get("type") != "TypeError":
            raise ValueError(f"{name} {label} type")
        python = python_value(decode(child))
        node = run_dump(node_cmd, json.dumps(child).encode("utf-8"))
        if python[0] != "err" or python[1] != "type_error":
            raise ValueError(f"{name} {label} python={python}")
        if node[0] != "err" or node[1] != "type_error":
            raise ValueError(f"{name} {label} node={node}")


def text_paths(directory: Path) -> list[Path]:
    paths = sorted(path for path in directory.glob("*.json") if path.is_file())
    if not paths:
        raise SystemExit(f"{directory} is empty")
    return paths


def check_text(directory: Path, rust_cmd: list[str]) -> int:
    failed = 0
    paths = text_paths(directory)
    for path in paths:
        try:
            check_text_file(path, rust_cmd)
        except Exception as err:
            failed += 1
            print(f"text {path.stem} ... FAILED")
            print(f"  {err}", file=sys.stderr)
        else:
            print(f"text {path.stem} rust-python ok")
    passed = len(paths) - failed
    print(f"text {passed} ok")
    if passed != len(paths):
        failed += 1
    return failed


def check_text_file(path: Path, rust_cmd: list[str]) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    keys = sorted(data)
    raw = decode_field(data["input_b64"])
    rust = run_dump(rust_cmd, raw)
    python = python_bytes(raw)
    if rust != python:
        raise ValueError(f"language mismatch rust={rust} python={python}")
    if keys == ["input_b64", "output_b64"]:
        expected_hex = decode_field(data["output_b64"]).hex()
        if rust[0] != "ok" or rust[1] != expected_hex or rust[2] != python[2]:
            raise ValueError(f"bytes differ got {rust}")
        return
    if keys == ["error", "input_b64"]:
        if rust != ("err", data["error"], None):
            raise ValueError(f"error differs got {rust}")
        return
    raise ValueError(f"illegal keys {keys}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--text", required=True, type=Path)
    parser.add_argument("--rust-dump", required=True)
    parser.add_argument("--node-binding", required=True)
    parser.add_argument("--node-dump", required=True)
    args = parser.parse_args()
    rust_cmd = [args.rust_dump]
    node_cmd = ["node", args.node_dump, args.node_binding]
    failed = check_reference(args.reference, rust_cmd, node_cmd)
    failed += check_text(args.text, rust_cmd)
    if failed:
        print("agreement: FAILED")
        return 1
    print("agreement: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
