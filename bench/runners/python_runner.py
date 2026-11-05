#!/usr/bin/env python3
"""Time the installed agent_receipts wheel. Plan on stdin, reply on stdout."""

import json
import sys
import time

import agent_receipts


def main() -> None:
    plan = json.load(sys.stdin)
    if plan.get("schema") != 1:
        raise SystemExit("schema")
    probes = []
    samples = []
    for case in plan["cases"]:
        operation = case["operation"]
        payload = case["payload"]
        call = bind(operation, payload)
        probes.append(
            {
                "operation": operation,
                "caseId": case["caseId"],
                "observed": normalize(operation, call()),
            }
        )
        samples.append(
            {
                "operation": operation,
                "caseId": case["caseId"],
                "ns": time_loop(case["warmup"], case["iterations"], call, operation),
            }
        )
    json.dump({"schema": 1, "probes": probes, "samples": samples}, sys.stdout)
    sys.stdout.write("\n")


def bind(operation: str, payload: object):
    if operation == "canonical_json":
        return lambda: agent_receipts.canonical_json(payload)
    if operation == "stable_hash":
        return lambda: agent_receipts.stable_hash(payload)
    if operation == "verify_audit_receipt":
        body = payload
        return lambda: agent_receipts.verify_audit_receipt(body["receipt"], body["key"])
    if operation == "verify_controlled_integrity":
        body = payload
        return lambda: agent_receipts.verify_controlled_integrity(
            body["value"], body["key"], body["keyId"], body["evidence"]
        )
    if operation == "compare_authority_contracts":
        body = payload
        return lambda: agent_receipts.compare_authority_contracts(body["previous"], body["next"])
    raise SystemExit(f"operation {operation}")


def normalize(operation: str, result: object) -> object:
    if operation in ("canonical_json", "stable_hash"):
        if not isinstance(result, str):
            raise SystemExit("probe string")
        return result
    if operation in ("verify_audit_receipt", "verify_controlled_integrity"):
        if not isinstance(result, bool):
            raise SystemExit("probe bool")
        return result
    if not isinstance(result, dict):
        raise SystemExit("probe compare")
    relationship = result["relationship"]
    widened = result["widened"]
    narrowed = result["narrowed"]
    if not isinstance(relationship, str):
        raise SystemExit("probe relationship")
    return {
        "relationship": relationship,
        "widened": list(widened),
        "narrowed": list(narrowed),
    }


def time_loop(warmup: int, iterations: int, call, operation: str) -> list[int]:
    sink = 0
    for _ in range(warmup):
        sink ^= observe(operation, call())
    samples = [0] * iterations
    for index in range(iterations):
        started = time.perf_counter_ns()
        result = call()
        sink ^= observe(operation, result)
        finished = time.perf_counter_ns()
        samples[index] = finished - started
    if sink < 0:
        raise SystemExit("observe")
    return samples


def observe(operation: str, result: object) -> int:
    if operation in ("canonical_json", "stable_hash"):
        if not isinstance(result, str):
            raise SystemExit("observe string")
        return len(result)
    if operation in ("verify_audit_receipt", "verify_controlled_integrity"):
        if not isinstance(result, bool):
            raise SystemExit("observe bool")
        return 1 if result else 0
    if not isinstance(result, dict):
        raise SystemExit("observe compare")
    relationship = result["relationship"]
    if not isinstance(relationship, str):
        raise SystemExit("observe relationship")
    return len(relationship)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as err:
        print(f"{type(err).__name__}: {err}", file=sys.stderr)
        raise SystemExit(1) from err
