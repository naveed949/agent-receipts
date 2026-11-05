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
    if root.get("count") != len(rows) or len(rows) != 23:
        raise SystemExit(f"count {root.get('count')} len {len(rows)}")
    return root


def check_reference(
    reference: Path,
    rust_cmd: list[str],
    node_cmd: list[str],
    rust_hmac: list[str],
    python_hmac: list[str],
    node_hmac: list[str],
) -> int:
    root = load_reference(reference / "vectors.json")
    allow = read_allowlist(reference / "pending-kinds.txt")
    pending_lines: list[str] = []
    seen: list[str] = []
    ok = 0
    hmac_ok = 0
    failed = 0
    hmac_kinds = ("controlled-integrity", "audit.verifyAuditReceipt")
    catalog = load_hmac_catalog(root["vectors"])
    hmac_dumps = (rust_hmac, python_hmac, node_hmac)
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
        if kind in hmac_kinds:
            try:
                check_hmac_row(row, name, catalog, hmac_dumps)
            except Exception as err:
                failed += 1
                print(f"hmac {name} ... FAILED")
                print(f"  {err}", file=sys.stderr)
            else:
                hmac_ok += 1
                print(f"hmac {name} ok")
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
    if (
        ok != 8
        or hmac_ok != 8
        or len(pending_lines) != 7
        or ok + hmac_ok + len(pending_lines) != 23
    ):
        failed += 1
        print(
            f"counts canonicalize {ok} hmac {hmac_ok} pending {len(pending_lines)}",
            file=sys.stderr,
        )
    try:
        check_gondolin_https(reference, catalog, hmac_dumps)
        print("hmac gondolin-https rust-python-node ok")
    except Exception as err:
        failed += 1
        print("hmac gondolin-https ... FAILED")
        print(f"  {err}", file=sys.stderr)
    print(f"pending {len(pending_lines)}")
    print(f"hmac {hmac_ok} ok")
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


HMAC_ROW_NAMES = (
    "hmac-controlled-sign-and-verify",
    "hmac-audit-receipt-valid",
    "hmac-audit-receipt-failures",
    "hmac-audit-keyid-swap",
    "hmac-audit-v1-artifact-hash-mismatch",
    "hmac-key-encoding-and-length",
    "linkage-version-rules",
    "hmac-audit-pre124-restamp",
)


def load_hmac_catalog(rows: list) -> dict:
    catalog = {}
    for row in rows:
        if row.get("name") == "hmac-audit-receipt-valid":
            catalog["v1_receipt"] = row["input"]["receipt"]
            catalog["v1_key"] = row["input"]["signingKeyUtf8"]
        if row.get("name") == "linkage-version-rules":
            catalog["v2_allowed"] = row["input"]["v2AllowedReceipt"]
            catalog["v2_denied"] = row["input"]["v2DeniedReceipt"]
            catalog["v2_key"] = row["input"]["signingKeyUtf8"]
    return catalog


def run_hmac_line(command: list[str], raw: bytes) -> str:
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
    lines = [line for line in completed.stdout.decode("utf-8").splitlines() if line != ""]
    if not lines:
        raise ValueError(f"{command[0]} produced no output")
    return lines[0]


def hmac_agree(label: str, payload: dict, dumps: tuple[list[str], list[str], list[str]]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    rust = run_hmac_line(dumps[0], raw)
    python = run_hmac_line(dumps[1], raw)
    node = run_hmac_line(dumps[2], raw)
    if rust != python or python != node:
        raise ValueError(f"{label} rust={rust} python={python} node={node}")
    return rust


def expect_bool(label: str, line: str, want: bool) -> None:
    expected = f"ok {'true' if want else 'false'}"
    if line != expected:
        raise ValueError(f"{label} got {line} want {expected}")


def check_hmac_row(
    row, name: str, catalog: dict, dumps: tuple[list[str], list[str], list[str]]
) -> None:
    import copy

    if name not in HMAC_ROW_NAMES:
        raise ValueError(f"unimplemented {name}")
    if name == "hmac-controlled-sign-and-verify":
        key = row["input"]["signingKeyUtf8"]
        key_id = row["input"]["keyId"]
        value = decode(row["input"]["value"])
        signed = hmac_agree(
            "controlled sign",
            {"op": "sign_controlled", "value": value, "key": key, "keyId": key_id},
            dumps,
        )
        if not signed.startswith("ok "):
            raise ValueError(f"controlled sign {signed}")
        evidence = json.loads(signed[3:])
        if evidence["integrityDigest"] != row["expected"]["sign"]["evidence"]["integrityDigest"]:
            raise ValueError("controlled digest")
        cases = row["input"]["verifyCases"]
        for label, want in row["expected"]["verify"].items():
            target = {"a": "y", "b": [1, 2]} if label == "tamperedValue" else value
            offered = cases["valid"] if label == "tamperedValue" else cases[label]
            line = hmac_agree(
                f"controlled {label}",
                {
                    "op": "verify_controlled",
                    "value": target,
                    "key": key,
                    "keyId": key_id,
                    "evidence": offered,
                },
                dumps,
            )
            expect_bool(f"controlled {label}", line, want)
        return
    if name == "hmac-audit-receipt-valid":
        key = row["input"]["signingKeyUtf8"]
        receipt = row["input"]["receipt"]
        line = hmac_agree(
            "audit valid",
            {"op": "verify_audit", "receipt": receipt, "key": key},
            dumps,
        )
        expect_bool("audit valid", line, row["expected"]["result"])
        document = copy.deepcopy(receipt)
        del document["integrity"]["signature"]
        hashed = hmac_agree(
            "macInputAscii",
            {"op": "stable_hash", "value": document},
            dumps,
        )
        if hashed != f"ok {row['expected']['macInputAscii']}":
            raise ValueError(f"macInputAscii {hashed}")
        resigned = hmac_agree(
            "audit resign",
            {"op": "resign", "receipt": receipt, "key": key},
            dumps,
        )
        if json.loads(resigned[3:])["integrity"]["signature"] != receipt["integrity"]["signature"]:
            raise ValueError("audit resign changed the tag")
        return
    if name == "hmac-audit-receipt-failures":
        key = catalog["v1_key"]
        receipt = catalog["v1_receipt"]
        expected = row["expected"]
        tampered = copy.deepcopy(receipt)
        tampered["outcome"] = "allowed"
        expect_bool(
            "tamperedOutcome",
            hmac_agree(
                "tamperedOutcome",
                {"op": "verify_audit", "receipt": tampered, "key": key},
                dumps,
            ),
            expected["tamperedOutcome"],
        )
        expect_bool(
            "wrongKey",
            hmac_agree(
                "wrongKey",
                {
                    "op": "verify_audit",
                    "receipt": receipt,
                    "key": "synthetic-audit-key-WRONG-0000000",
                },
                dumps,
            ),
            expected["wrongKey"],
        )
        upper = copy.deepcopy(receipt)
        upper["integrity"]["signature"] = upper["integrity"]["signature"].upper()
        expect_bool(
            "uppercaseSignature",
            hmac_agree(
                "uppercaseSignature",
                {"op": "verify_audit", "receipt": upper, "key": key},
                dumps,
            ),
            expected["uppercaseSignature"],
        )
        marked = copy.deepcopy(receipt)
        marked["authorityPolicyVersion"] = "2"
        expect_bool(
            "v2DiscriminatorResigned",
            hmac_agree(
                "v2DiscriminatorResigned",
                {"op": "resign_then_verify", "receipt": marked, "key": key},
                dumps,
            ),
            expected["v2DiscriminatorResigned"],
        )
        expect_bool(
            "nullReceipt",
            hmac_agree(
                "nullReceipt",
                {"op": "verify_audit", "receipt": None, "key": key},
                dumps,
            ),
            expected["nullReceipt"],
        )
        missing = copy.deepcopy(receipt)
        del missing["integrity"]
        expect_bool(
            "missingIntegrity",
            hmac_agree(
                "missingIntegrity",
                {"op": "verify_audit", "receipt": missing, "key": key},
                dumps,
            ),
            expected["missingIntegrity"],
        )
        return
    if name == "hmac-audit-keyid-swap":
        receipt = catalog["v1_receipt"]
        key = catalog["v1_key"]
        swapped = copy.deepcopy(receipt)
        swapped["integrity"]["keyId"] = "synthetic-key-b"
        expect_bool(
            "keyid swap",
            hmac_agree(
                "keyid swap",
                {"op": "verify_audit", "receipt": swapped, "key": key},
                dumps,
            ),
            row["expected"]["swappedKeyIdOldSignature"],
        )
        expect_bool(
            "keyid control",
            hmac_agree(
                "keyid control",
                {"op": "verify_audit", "receipt": receipt, "key": key},
                dumps,
            ),
            row["expected"]["control_unchanged"],
        )
        return
    if name == "hmac-audit-v1-artifact-hash-mismatch":
        key = catalog["v1_key"]
        mismatched = copy.deepcopy(catalog["v1_receipt"])
        mismatched["artifacts"]["request"]["hash"] = "0" * 64
        expect_bool(
            "v1 hash mismatch",
            hmac_agree(
                "v1 hash mismatch",
                {"op": "resign_then_verify", "receipt": mismatched, "key": key},
                dumps,
            ),
            row["expected"]["mismatchReMaced"],
        )
        expect_bool(
            "v1 hash control",
            hmac_agree(
                "v1 hash control",
                {"op": "resign_then_verify", "receipt": catalog["v1_receipt"], "key": key},
                dumps,
            ),
            row["expected"]["control_reMacedUnchanged"],
        )
        return
    if name == "hmac-key-encoding-and-length":
        key = catalog["v1_key"]
        expected = row["expected"]
        expect_bool(
            "key as bytes",
            hmac_agree(
                "key as bytes",
                {
                    "op": "verify_audit",
                    "receipt": catalog["v1_receipt"],
                    "key": key,
                    "as": "bytes",
                },
                dumps,
            ),
            expected["keyAsUtf8Bytes"],
        )
        expect_bool(
            "fiveCharKey",
            hmac_agree(
                "fiveCharKey",
                {"op": "resign_then_verify", "receipt": catalog["v1_receipt"], "key": "short"},
                dumps,
            ),
            expected["fiveCharKey"],
        )
        short = hmac_agree(
            "runtimeRejectsShortKey",
            {"op": "audit_signing_key", "key": "short"},
            dumps,
        )
        if short != f"err {expected['runtimeRejectsShortKey']['error']['message']}":
            raise ValueError(f"runtimeRejectsShortKey {short}")
        eight = "é" * 8
        eight_line = hmac_agree(
            "runtimeEightNonAsciiChars",
            {"op": "audit_signing_key", "key": eight, "utf16Len": 8},
            dumps,
        )
        if eight_line != f"err {expected['runtimeEightNonAsciiChars']['error']['message']}":
            raise ValueError(f"runtimeEightNonAsciiChars {eight_line}")
        controlled_ok = hmac_agree(
            "controlledEightNonAscii",
            {"op": "controlled_signing_key", "key": eight},
            dumps,
        )
        if controlled_ok != "ok":
            raise ValueError(f"controlledEightNonAscii {controlled_ok}")
        fifteen = hmac_agree(
            "controlledFifteenByteKey",
            {"op": "controlled_signing_key", "key": "a" * 15, "as": "bytes"},
            dumps,
        )
        if fifteen != f"err {expected['controlledFifteenByteKey']['error']['message']}":
            raise ValueError(f"controlledFifteenByteKey {fifteen}")
        return
    if name == "linkage-version-rules":
        key = catalog["v2_key"]
        expected = row["expected"]
        expect_bool(
            "v2 allowed",
            hmac_agree(
                "v2 allowed",
                {"op": "verify_audit", "receipt": catalog["v2_allowed"], "key": key},
                dumps,
            ),
            expected["v2AllowedReceipt"],
        )
        expect_bool(
            "v2 denied",
            hmac_agree(
                "v2 denied",
                {"op": "verify_audit", "receipt": catalog["v2_denied"], "key": key},
                dumps,
            ),
            expected["v2DeniedReceipt"],
        )
        for label, want in expected["v2Mutations"].items():
            mutated = apply_v2_mutation(catalog["v2_allowed"], label)
            expect_bool(
                f"v2 {label}",
                hmac_agree(
                    f"v2 {label}",
                    {"op": "resign_then_verify", "receipt": mutated, "key": key},
                    dumps,
                ),
                want,
            )
        v1_key = catalog["v1_key"]
        for label, want in expected["v1Mutations"].items():
            mutated = apply_v1_mutation(catalog["v1_receipt"], label)
            expect_bool(
                f"v1 {label}",
                hmac_agree(
                    f"v1 {label}",
                    {"op": "resign_then_verify", "receipt": mutated, "key": v1_key},
                    dumps,
                ),
                want,
            )
        return
    if name == "hmac-audit-pre124-restamp":
        expected = row["expected"]
        for label in ("v1", "v2"):
            case = row["input"][label]
            key = case["signingKeyUtf8"]
            receipt = case["receipt"]
            expect_bool(
                f"{label} as issued",
                hmac_agree(
                    f"{label} as issued",
                    {"op": "verify_audit", "receipt": receipt, "key": key},
                    dumps,
                ),
                expected[f"{label}AsIssued"],
            )
            restamped = hmac_agree(
                f"{label} restamp",
                {"op": "resign", "receipt": receipt, "key": key},
                dumps,
            )
            if not restamped.startswith("ok "):
                raise ValueError(f"{label} restamp {restamped}")
            body = json.loads(restamped[3:])
            if body["integrity"]["signature"] != expected[f"{label}RestampedSignature"]:
                raise ValueError(f"{label} restamp signature")
            expect_bool(
                f"{label} restamped",
                hmac_agree(
                    f"{label} restamped",
                    {"op": "verify_audit", "receipt": body, "key": key},
                    dumps,
                ),
                expected[f"{label}Restamped"],
            )
        return
    raise ValueError(f"unimplemented {name}")


def check_gondolin_https(
    reference: Path, catalog: dict, dumps: tuple[list[str], list[str], list[str]]
) -> None:
    import copy

    spec_path = reference.parent / "hmac" / "gondolin-https.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    expected = spec["expected"]
    marked_v1 = copy.deepcopy(catalog["v1_receipt"])
    marked_v1["gondolinHttps"] = True
    expect_bool(
        "gondolin v1",
        hmac_agree(
            "gondolin v1",
            {"op": "resign_then_verify", "receipt": marked_v1, "key": catalog["v1_key"]},
            dumps,
        ),
        expected["v1WithGondolinHttpsResigned"],
    )
    marked_v2 = copy.deepcopy(catalog["v2_allowed"])
    marked_v2["gondolinHttps"] = True
    expect_bool(
        "gondolin v2",
        hmac_agree(
            "gondolin v2",
            {"op": "resign_then_verify", "receipt": marked_v2, "key": catalog["v2_key"]},
            dumps,
        ),
        expected["v2WithGondolinHttpsResigned"],
    )


def apply_v2_mutation(receipt, label):
    import copy

    receipt = copy.deepcopy(receipt)
    if label == "resignedUnchanged_control":
        return receipt
    if label == "versionTagV1WithMarker2":
        receipt["version"] = "adaptive-sandbox.audit-receipt/v1"
        return receipt
    if label == "markerRemovedV2Tag":
        del receipt["authorityPolicyVersion"]
        return receipt
    if label == "marker3":
        receipt["authorityPolicyVersion"] = "3"
        return receipt
    if label == "policyArtifactVersionLabel1":
        receipt["artifacts"]["policy"]["version"] = "1"
        return receipt
    if label == "planEnvelopeVersion1":
        receipt["artifacts"]["plan"]["value"]["authority"]["version"] = "1"
        return refresh_hashes(receipt)
    if label == "planAuthorityHashUppercase":
        receipt["artifacts"]["plan"]["value"]["authorityHash"] = receipt["artifacts"]["plan"][
            "value"
        ]["authorityHash"].upper()
        return receipt
    if label == "artifactHashMismatch":
        receipt["artifacts"]["policy"]["hash"] = "0" * 64
        return receipt
    if label == "argumentAuthorityVersion1":
        receipt["artifacts"]["plan"]["value"]["argumentAuthority"]["version"] = "1"
        return refresh_hashes(receipt)
    if label == "backendMarker1":
        receipt["artifacts"]["backend"]["value"]["authorityPolicyVersion"] = "1"
        return refresh_hashes(receipt)
    if label == "backendAuthorityVersion1":
        receipt["artifacts"]["backend"]["value"]["authority"]["version"] = "1"
        return refresh_hashes(receipt)
    if label.startswith("policyLayer_") and label.endswith("_version1"):
        layer = label[len("policyLayer_") : -len("_version1")]
        receipt["artifacts"]["policy"]["value"][layer]["version"] = "1"
        return refresh_hashes(receipt)
    if label == "contractGrantsVersion1":
        receipt["artifacts"]["contract"]["value"]["authority"]["grants"]["version"] = "1"
        return refresh_hashes(receipt)
    if label == "requestAgentAuthorityVersion1":
        receipt["artifacts"]["request"]["value"]["agent"]["authority"]["version"] = "1"
        return refresh_hashes(receipt)
    if label == "requestSessionAuthorityVersion1":
        receipt["artifacts"]["request"]["value"]["session"]["authority"]["version"] = "1"
        return refresh_hashes(receipt)
    if label == "grantedDiffersFromEnvelope":
        receipt["authority"]["granted"]["authority"]["network"] = {}
        return receipt
    if label == "grantedRemoved":
        del receipt["authority"]["granted"]["authority"]
        return receipt
    raise ValueError(f"unknown v2 mutation {label}")


def apply_v1_mutation(receipt, label):
    import copy

    receipt = copy.deepcopy(receipt)
    if label == "resignedUnchanged_control":
        return receipt
    if label == "versionTagV2NoMarker":
        receipt["version"] = "adaptive-sandbox.audit-receipt/v2"
        return receipt
    if label == "planEnvelopeVersion2":
        receipt["artifacts"]["plan"]["value"]["authority"] = {"version": "2"}
        return refresh_hashes(receipt)
    if label == "planEnvelopeVersion1Explicit":
        receipt["artifacts"]["plan"]["value"]["authority"] = {"version": "1"}
        return refresh_hashes(receipt)
    if label == "grantedVersion2":
        receipt["authority"]["granted"]["authority"] = {"version": "2"}
        return receipt
    raise ValueError(f"unknown v1 mutation {label}")


def refresh_hashes(receipt):
    import agent_receipts as receipts

    for entry in receipt["artifacts"].values():
        entry["hash"] = receipts.stable_hash(entry["value"])
    return receipt


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
    parser.add_argument("--rust-hmac-dump", required=True)
    parser.add_argument("--python-hmac-dump", required=True)
    parser.add_argument("--node-hmac-dump", required=True)
    args = parser.parse_args()
    rust_cmd = [args.rust_dump]
    node_cmd = ["node", args.node_dump, args.node_binding]
    rust_hmac = [args.rust_hmac_dump]
    python_hmac = [sys.executable, args.python_hmac_dump]
    node_hmac = ["node", args.node_hmac_dump, args.node_binding]
    failed = check_reference(
        args.reference, rust_cmd, node_cmd, rust_hmac, python_hmac, node_hmac
    )
    failed += check_text(args.text, rust_cmd)
    if failed:
        print("agreement: FAILED")
        return 1
    print("agreement: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
