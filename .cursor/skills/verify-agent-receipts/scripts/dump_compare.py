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
