#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path


def decode_field(field: str) -> bytes:
    raw = base64.standard_b64decode(field)
    encoded = base64.standard_b64encode(raw).decode("ascii")
    if encoded != field:
        raise ValueError(f"base64 field {field} encodes as {encoded}")
    return raw


def parse_dump(text: str) -> tuple[str, str]:
    line = text.strip()
    if line.startswith("ok "):
        return ("ok", line[3:].strip())
    if line.startswith("err "):
        return ("err", line[4:].strip())
    raise ValueError(f"dump output was not ok/err: {text!r}")


def run_dump(command: list[str], raw: bytes) -> tuple[str, str]:
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
    return parse_dump(completed.stdout.decode("ascii"))


def python_dump(raw: bytes) -> tuple[str, str]:
    import agent_receipts

    try:
        output = agent_receipts.canonicalize_bytes(raw)
    except agent_receipts.CanonicalizeError as err:
        return ("err", str(err.code))
    if type(output) is not bytes:
        raise TypeError(f"Python returned {type(output)!r}, want bytes")
    return ("ok", output.hex())


def vector_paths(vectors: Path) -> list[Path]:
    paths = sorted(path for path in vectors.glob("*.json") if path.is_file())
    if not paths:
        raise SystemExit(f"{vectors} is empty")
    return paths


def check_vector(
    path: Path,
    rust_cmd: list[str],
    node_cmd: list[str],
) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    keys = sorted(data)
    raw = decode_field(data["input_b64"])
    rust = run_dump(rust_cmd, raw)
    python = python_dump(raw)
    node = run_dump(node_cmd, raw)
    if rust != python or python != node:
        raise ValueError(
            f"language mismatch rust={rust} python={python} node={node}"
        )
    if keys == ["input_b64", "output_b64"]:
        expected = ("ok", decode_field(data["output_b64"]).hex())
        if rust != expected:
            raise ValueError(f"bytes differ from vector: got {rust} want {expected}")
        return
    if keys == ["error", "input_b64"]:
        expected = ("err", data["error"])
        if rust != expected:
            raise ValueError(f"error differs from vector: got {rust} want {expected}")
        return
    raise ValueError(f"illegal keys {keys}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", required=True, type=Path)
    parser.add_argument("--rust-dump", required=True)
    parser.add_argument("--node-binding", required=True)
    parser.add_argument("--node-dump", required=True)
    args = parser.parse_args()

    rust_cmd = [args.rust_dump]
    node_cmd = ["node", args.node_dump, args.node_binding]
    failed = 0
    paths = vector_paths(args.vectors)
    print(f"comparing {len(paths)} vectors across Rust, Python, and Node")
    for path in paths:
        try:
            check_vector(path, rust_cmd, node_cmd)
        except Exception as err:
            failed += 1
            print(f"{path.name} ... FAILED")
            print(f"  {err}", file=sys.stderr)
        else:
            print(f"{path.name} ... ok")
    passed = len(paths) - failed
    if failed:
        print(f"agreement: FAILED. {passed} passed; {failed} failed")
        return 1
    print(f"agreement: ok. {passed} passed; 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
