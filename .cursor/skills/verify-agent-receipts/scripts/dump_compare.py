#!/usr/bin/env python3
from __future__ import annotations

import json
import sys

import agent_receipts as receipts


class DuplicateKey(ValueError):
    pass


def reject_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise DuplicateKey(key)
        out[key] = value
    return out


def main() -> int:
    try:
        cmd = json.loads(sys.stdin.read(), object_pairs_hook=reject_duplicate_keys)
    except DuplicateKey:
        print("err invalid_input")
        return 0
    except json.JSONDecodeError as err:
        print(f"err parse {err}")
        return 0
    print(run(cmd))
    return 0


def run(cmd) -> str:
    try:
        got = receipts.compare_authority_contracts(cmd.get("previous"), cmd.get("next"))
    except TypeError:
        return "err TypeError"
    except Exception as err:
        return f"err {err}"
    payload = {
        "relationship": got["relationship"],
        "widened": list(got["widened"]),
        "narrowed": list(got["narrowed"]),
    }
    return "ok " + json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


if __name__ == "__main__":
    raise SystemExit(main())
