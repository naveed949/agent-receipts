#!/usr/bin/env python3
from __future__ import annotations

import json
import sys

import agent_receipts as receipts


def main() -> int:
    try:
        cmd = json.loads(sys.stdin.read())
    except json.JSONDecodeError as err:
        print(f"err parse {err}")
        return 0
    print(run(cmd))
    return 0


def run(cmd) -> str:
    try:
        return dispatch(cmd)
    except Exception as err:
        code = getattr(err, "code", None)
        return f"err {code if code else err}"


def dispatch(cmd) -> str:
    op = cmd.get("op")
    if op == "verify_audit":
        return f"ok {py_bool(receipts.verify_audit_receipt(cmd.get('receipt'), key_value(cmd)))}"
    if op == "resign":
        resigned = receipts.resign_audit_receipt(cmd.get("receipt"), key_value(cmd))
        return f"ok {receipts.canonical_json(resigned)}"
    if op == "resign_then_verify":
        key = key_value(cmd)
        resigned = receipts.resign_audit_receipt(cmd.get("receipt"), key)
        return f"ok {py_bool(receipts.verify_audit_receipt(resigned, key))}"
    if op == "verify_controlled":
        return f"ok {py_bool(receipts.verify_controlled_integrity(cmd.get('value'), key_value(cmd), cmd.get('keyId'), cmd.get('evidence')))}"
    if op == "sign_controlled":
        evidence = receipts.sign_controlled_integrity(
            cmd.get("value"), key_value(cmd), cmd.get("keyId")
        )
        return f"ok {receipts.canonical_json(evidence)}"
    if op == "audit_signing_key":
        receipts.audit_signing_key(key_value(cmd))
        return "ok"
    if op == "controlled_signing_key":
        receipts.controlled_signing_key(key_value(cmd))
        return "ok"
    if op == "stable_hash":
        return f"ok {receipts.stable_hash(cmd.get('value'))}"
    return f"err unknown op {op}"


def key_value(cmd):
    if "key" not in cmd or cmd["key"] is None:
        raise ValueError("missing key")
    key = cmd["key"]
    if cmd.get("as") == "bytes":
        if isinstance(key, str):
            return key.encode("utf-8")
        return bytes(key)
    return key


def py_bool(flag) -> str:
    return "true" if flag else "false"


if __name__ == "__main__":
    raise SystemExit(main())
