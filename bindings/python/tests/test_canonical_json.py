import base64
import copy
import json
import math
from datetime import datetime
from pathlib import Path

import pytest

from agent_receipts import (
    CanonicalizeError,
    audit_signing_key,
    canonical_json,
    compare_authority_contracts,
    controlled_signing_key,
    is_https_authority_subset,
    normalize_authority_policy,
    normalize_https_authority_rules,
    resign_audit_receipt,
    sign_controlled_integrity,
    stable_hash,
    verify_audit_receipt,
    verify_controlled_integrity,
)

ROOT = Path(__file__).resolve().parents[3]
REFERENCE = ROOT / "vectors" / "reference"
TEXT = ROOT / "vectors" / "text"
TEXT_NAMES = [
    "duplicate-escaped.json",
    "duplicate-key.json",
    "integer-above-safe.json",
    "invalid-json.json",
    "lone-surrogate.json",
    "negative-zero.json",
    "not-utf8.json",
    "number-1e2.json",
    "trailing-value.json",
]


class Missing:
    pass


class RejectedInteger:
    def __init__(self, digits):
        self.digits = digits


def test_exports():
    assert not hasattr(__import__("agent_receipts"), "canonicalize_bytes")


def test_verify_never_raises():
    assert verify_audit_receipt(None, "synthetic-audit-key-0123456789ab") is False
    assert verify_audit_receipt({"version": "nope"}, 1) is False
    assert verify_controlled_integrity({"a": "x"}, "synthetic-controlled-key-0001", 1, {}) is False
    assert verify_controlled_integrity(None, None, None, None) is False


def test_gondolin_https_is_v1_only():
    root = json.loads((REFERENCE / "vectors.json").read_text(encoding="utf-8"))
    catalog = load_catalog(root["vectors"])
    spec = json.loads((ROOT / "vectors" / "hmac" / "gondolin-https.json").read_text(encoding="utf-8"))
    marked_v1 = copy.deepcopy(catalog["v1_receipt"])
    marked_v1["gondolinHttps"] = True
    assert (
        verify_audit_receipt(resign_audit_receipt(marked_v1, catalog["v1_key"]), catalog["v1_key"])
        is spec["expected"]["v1WithGondolinHttpsResigned"]
    )
    marked_v2 = copy.deepcopy(catalog["v2_allowed"])
    marked_v2["gondolinHttps"] = True
    assert (
        verify_audit_receipt(resign_audit_receipt(marked_v2, catalog["v2_key"]), catalog["v2_key"])
        is spec["expected"]["v2WithGondolinHttpsResigned"]
    )


def test_reference_vectors(capsys):
    failures = []
    root = load_reference()
    allow = read_allowlist(REFERENCE / "pending-kinds.txt")
    count = root["count"]
    rows = root["vectors"]
    if count != len(rows) or len(rows) != 23:
        failures.append(f"count {count} len {len(rows)}")
        rows = []

    catalog = load_catalog(rows)
    pending_lines = []
    seen = []
    canonical_ok = 0
    hmac_ok = 0
    compare_ok = 0
    for row in rows:
        name = require_str(row, "name", failures)
        kind = require_str(row, "kind", failures)
        if name is None or kind is None:
            continue
        if kind == "canonicalize":
            try:
                check_canonicalize(row, name)
            except Exception as err:
                failures.append(f"{name} {err}")
            else:
                canonical_ok += 1
            continue
        if kind in ("controlled-integrity", "audit.verifyAuditReceipt"):
            try:
                check_hmac_row(row, name, catalog)
            except Exception as err:
                failures.append(f"{name} {err}")
            else:
                hmac_ok += 1
            continue
        if kind == "compareAuthorityContracts":
            try:
                check_compare(row, name)
            except Exception as err:
                failures.append(f"{name} {err}")
            else:
                compare_ok += 1
            continue
        if kind not in allow:
            failures.append(f"unknown kind {kind}")
            continue
        if kind not in seen:
            seen.append(kind)
        pending_lines.append(f"pending {kind} {name}")
    for kind in allow:
        if kind not in seen:
            failures.append(f"unused pending kind {kind}")
    if rows and (
        canonical_ok != 8
        or hmac_ok != 8
        or compare_ok != 7
        or len(pending_lines) != 0
        or canonical_ok + hmac_ok + compare_ok + len(pending_lines) != 23
    ):
        failures.append(
            f"counts canonicalize {canonical_ok} hmac {hmac_ok} compare {compare_ok} pending {len(pending_lines)}"
        )
    for line in pending_lines:
        print(line)
    print(f"pending {len(pending_lines)}")
    print(f"canonicalize {canonical_ok} ok")
    print(f"hmac {hmac_ok} ok")
    print(f"compare {compare_ok} ok")
    captured = capsys.readouterr().out
    for line in pending_lines:
        assert line in captured
    assert f"pending {len(pending_lines)}\n" in captured
    assert f"canonicalize {canonical_ok} ok\n" in captured
    assert f"hmac {hmac_ok} ok\n" in captured
    assert f"compare {compare_ok} ok\n" in captured
    assert not failures, "\n".join(failures)


def test_text_names_match():
    names = sorted(path.name for path in TEXT.glob("*.json"))
    assert names == sorted(TEXT_NAMES)


@pytest.mark.parametrize("name", TEXT_NAMES)
def test_text_vector(name):
    data = json.loads((TEXT / name).read_text(encoding="utf-8"))
    keys = set(data)
    raw = decode_field(data["input_b64"])
    if keys == {"input_b64", "output_b64"}:
        expected = decode_field(data["output_b64"]).decode("utf-8")
        got = canonical_json(raw)
        assert type(got) is str
        assert got == expected
        assert canonical_json(got.encode("utf-8")) == got
        digest = stable_hash(raw)
        assert digest == stable_hash(got.encode("utf-8"))
        assert len(digest) == 64
        return
    if keys == {"input_b64", "error"}:
        assert_code(raw, data["error"])
        return
    raise AssertionError(f"illegal keys in {name}: {sorted(keys)}")


def test_bytes_and_text_agree_on_the_usage_object():
    raw = b'{"b":1,"a":2}'
    assert canonical_json(raw) == '{"a":2,"b":1}'
    assert stable_hash(raw) == (
        "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772"
    )
    assert canonical_json(bytearray(raw)) == '{"a":2,"b":1}'
    value = {
        "b": 1,
        "a": {"d": [3, {"z": True, "y": None}], "c": "x"},
        "B": 2,
        "_": 0,
    }
    assert canonical_json(value) == (
        '{"B":2,"_":0,"a":{"c":"x","d":[3,{"y":null,"z":true}]},"b":1}'
    )
    assert stable_hash(value) == (
        "5588b64560343c75cefb360b90918927a446fa3131288ef20c4ec67aaf4381f0"
    )


def test_string_is_a_json_string():
    assert canonical_json("hello") == '"hello"'
    assert canonical_json(b'"hello"') == '"hello"'
    assert canonical_json('{"a":1}') == '"{\\"a\\":1}"'
    assert canonical_json(None) == "null"
    assert canonical_json(True) == "true"
    assert canonical_json(False) == "false"
    assert canonical_json(1) == "1"
    assert canonical_json([]) == "[]"
    assert canonical_json({}) == "{}"


def test_lone_surrogate_and_negative_zero():
    assert math.copysign(1.0, -0.0) < 0
    assert canonical_json(-0.0) == "0"
    assert canonical_json(0.0) == "0"
    assert canonical_json("\ud800") == '"\\ud800"'
    assert stable_hash("\ud800") == stable_hash(b'"\\ud800"')


def test_exact_ints_and_host_rejects():
    assert canonical_json(2**53) == "9007199254740992"
    assert_code(2**53 + 1, "type_error")
    assert_code(10**10000, "type_error")
    assert_code(float("nan"), "type_error")
    assert_code(float("inf"), "type_error")
    assert_code(float("-inf"), "type_error")
    assert_code((), "type_error")
    assert_code(set(), "type_error")
    assert_code(frozenset(), "type_error")
    assert_code(memoryview(b"[]"), "type_error")
    assert_code(datetime(2020, 1, 1), "type_error")
    assert_code(1j, "type_error")
    assert_code([b"a"], "type_error")
    assert_code({1: "a"}, "type_error")

    class Bag(dict):
        pass

    class Items(list):
        pass

    class Word(str):
        pass

    class Count(int):
        pass

    assert_code(Bag(), "type_error")
    assert_code(Items(), "type_error")
    assert_code(Word("a"), "type_error")
    assert_code(Count(1), "type_error")


def test_cycles_depth_and_shared_values():
    loop = []
    loop.append(loop)
    assert_code(loop, "cycle")
    obj = {}
    obj["self"] = obj
    assert_code(obj, "cycle")
    shared = {"k": 1}
    assert canonical_json({"a": shared, "b": shared}) == '{"a":{"k":1},"b":{"k":1}}'
    assert canonical_json(nest(128)) == "[" * 128 + "null" + "]" * 128
    assert_code(nest(129), "too_deep")
    assert_code(nest_leaf(128, datetime(2020, 1, 1)), "type_error")
    assert_code(nest_leaf(128, b"x"), "type_error")
    assert_code(nest_leaf(128, ()), "type_error")

    class Bag:
        pass

    assert_code(nest_leaf(128, Bag()), "type_error")
    assert canonical_json(nest_leaf(128, "hi")) == "[" * 128 + '"hi"' + "]" * 128
    assert canonical_json(nest_objects(128)) == '{"k":' * 127 + "{}" + "}" * 127
    assert_code(nest_objects(129), "too_deep")
    assert_code(nest_leaf(128, {}), "too_deep")


def load_reference():
    text = (REFERENCE / "vectors.json").read_text(encoding="utf-8")
    if text == "":
        raise AssertionError("vectors.json is empty")
    root = json.loads(text, parse_int=float, parse_float=float)
    if not isinstance(root, dict):
        raise AssertionError("vectors.json is not an object")
    return root


def read_allowlist(path):
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line == "":
            continue
        if line == "canonicalize":
            raise AssertionError("allowlist contains canonicalize")
        if line in lines:
            raise AssertionError(f"duplicate pending kind {line}")
        lines.append(line)
    return lines


def require_str(row, field, failures):
    value = row.get(field)
    if type(value) is not str:
        failures.append(f"missing {field}")
        return None
    return value


def check_compare(row, name):
    has_expected = "expected" in row
    has_error = "expectedError" in row
    if has_expected == has_error:
        raise AssertionError("needs expected or expectedError")
    if has_expected:
        got = compare_authority_contracts(row["input"]["previous"], row["input"]["next"])
        want = row["expected"]
        if got["relationship"] != want["relationship"]:
            raise AssertionError(f"{name} relationship {got['relationship']}")
        if list(got["widened"]) != list(want["widened"]):
            raise AssertionError(f"{name} widened {got['widened']}")
        if list(got["narrowed"]) != list(want["narrowed"]):
            raise AssertionError(f"{name} narrowed {got['narrowed']}")
        return
    cases = row["input"]["cases"]
    expected_error = row["expectedError"]
    if set(cases) != set(expected_error):
        raise AssertionError(f"{name} rejection keys")
    for label, child in cases.items():
        spec = expected_error[label]
        if spec.get("type") != "TypeError":
            raise AssertionError(f"{name} {label} type")
        try:
            compare_authority_contracts(child["previous"], child["next"])
        except CanonicalizeError as err:
            raise AssertionError(f"{name} {label} CanonicalizeError {err}") from err
        except TypeError as err:
            if type(err) is not TypeError:
                raise AssertionError(f"{name} {label} class {type(err)!r}") from err
        else:
            raise AssertionError(f"{name} {label} accepted")


def test_https_helpers_call_rust():
    merged = [
        {
            "protocol": "https",
            "host": "API.example.com",
            "port": 443,
            "methods": ["HEAD", "GET"],
            "resolution": "public-only",
            "redirects": "none",
            "maxResponseBytes": 1024,
            "timeoutMs": 1000,
        }
    ]
    split = [
        {
            "protocol": "https",
            "host": "api.example.com",
            "port": 443,
            "methods": ["GET"],
            "resolution": "public-only",
            "redirects": "none",
            "maxResponseBytes": 1024,
            "timeoutMs": 1000,
        },
        {
            "protocol": "https",
            "host": "api.example.com",
            "port": 443,
            "methods": ["HEAD"],
            "resolution": "public-only",
            "redirects": "none",
            "maxResponseBytes": 1024,
            "timeoutMs": 1000,
        },
    ]
    assert is_https_authority_subset(split, merged) is True
    assert is_https_authority_subset(merged, split) is True
    normalize_https_authority_rules(split)
    normalize_authority_policy({"version": "2", "network": {"https": split}})


def test_compare_host_rejects_are_type_error():
    try:
        compare_authority_contracts(datetime.now(), {})
    except CanonicalizeError as err:
        raise AssertionError("CanonicalizeError") from err
    except TypeError as err:
        assert type(err) is TypeError
    else:
        raise AssertionError("accepted datetime")
    try:
        is_https_authority_subset(set(), [])
    except CanonicalizeError as err:
        raise AssertionError("CanonicalizeError") from err
    except TypeError as err:
        assert type(err) is TypeError
    else:
        raise AssertionError("accepted set")


def check_canonicalize(row, name):
    has_expected = "expected" in row
    has_error = "expectedError" in row
    if has_expected == has_error:
        raise AssertionError("needs expected or expectedError")
    if has_expected:
        check_success(row["input"], row["expected"], name)
        return
    check_rejections(row["input"], row["expectedError"], name)


def check_success(value, expected, name):
    decoded = decode(value)
    text = canonical_json(decoded)
    digest = stable_hash(decoded)
    assert type(text) is str
    assert type(digest) is str
    got_hex = text.encode("utf-8").hex()
    if got_hex != expected["canonicalUtf8Hex"]:
        raise AssertionError(f"{name} bytes {got_hex}")
    if digest != expected["stableHash"]:
        raise AssertionError(f"{name} hash {digest}")
    again = canonical_json(text.encode("utf-8"))
    if again != text:
        raise AssertionError(f"{name} is not stable")
    if stable_hash(text.encode("utf-8")) != digest:
        raise AssertionError(f"{name} second hash")


def check_rejections(value, expected_error, name):
    if not isinstance(value, dict) or "cases" not in value:
        raise AssertionError(f"{name} has no cases")
    cases = value["cases"]
    if not isinstance(cases, dict) or not isinstance(expected_error, dict):
        raise AssertionError(f"{name} rejection shape")
    if not cases or set(cases) != set(expected_error):
        raise AssertionError(f"{name} rejection keys")
    for label, child in cases.items():
        spec = expected_error[label]
        if not isinstance(spec, dict) or spec.get("type") != "TypeError":
            raise AssertionError(f"{name} {label} type")
        decoded = decode(child)
        try:
            canonical_json(decoded)
        except CanonicalizeError as err:
            if err.code != "type_error":
                raise AssertionError(f"{name} {label} {err.code}") from err
        else:
            raise AssertionError(f"{name} {label} accepted")
        try:
            stable_hash(decoded)
        except CanonicalizeError as err:
            if err.code != "type_error":
                raise AssertionError(f"{name} {label} hash {err.code}") from err
        else:
            raise AssertionError(f"{name} {label} hash accepted")


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
        raise AssertionError("tag is not a string")
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
        raise AssertionError(f"unknown tag {text}")
    if text.startswith("number:"):
        return parse_number(text[len("number:") :])
    raise AssertionError(f"unknown tag {text}")


def parse_number(token):
    if token == "" or any(char.isspace() for char in token):
        raise AssertionError(f"unknown tag number:{token}")
    if not (token[0] == "-" or token[0].isdigit()):
        raise AssertionError(f"unknown tag number:{token}")
    try:
        value = json.loads(token, parse_int=float, parse_float=float)
    except json.JSONDecodeError as err:
        raise AssertionError(f"unknown tag number:{token}") from err
    if type(value) is not float:
        raise AssertionError(f"unknown tag number:{token}")
    return value


def assert_code(value, code):
    with pytest.raises(CanonicalizeError) as caught:
        canonical_json(value)
    assert caught.value.code == code
    assert str(caught.value) == code
    with pytest.raises(CanonicalizeError) as hashed:
        stable_hash(value)
    assert hashed.value.code == code


def decode_field(field):
    raw = base64.standard_b64decode(field)
    encoded = base64.standard_b64encode(raw).decode("ascii")
    assert encoded == field
    return raw


def nest(depth):
    return nest_leaf(depth, None)


def nest_leaf(depth, leaf):
    value = leaf
    for _ in range(depth):
        value = [value]
    return value


def nest_objects(depth):
    value = {}
    for _ in range(1, depth):
        value = {"k": value}
    return value


def load_catalog(rows):
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


def check_hmac_row(row, name, catalog):
    if name == "hmac-controlled-sign-and-verify":
        check_controlled(row)
        return
    if name == "hmac-audit-receipt-valid":
        check_audit_valid(row)
        return
    if name == "hmac-audit-receipt-failures":
        check_audit_failures(row, catalog)
        return
    if name == "hmac-audit-keyid-swap":
        check_keyid_swap(row, catalog)
        return
    if name == "hmac-audit-v1-artifact-hash-mismatch":
        check_v1_hash_mismatch(row, catalog)
        return
    if name == "hmac-key-encoding-and-length":
        check_key_encoding(row, catalog)
        return
    if name == "linkage-version-rules":
        check_linkage(row, catalog)
        return
    if name == "hmac-audit-pre124-restamp":
        check_restamp(row)
        return
    raise AssertionError(f"unimplemented {name}")


def check_controlled(row):
    key = row["input"]["signingKeyUtf8"]
    key_id = row["input"]["keyId"]
    value = decode(row["input"]["value"])
    evidence = sign_controlled_integrity(value, key, key_id)
    assert evidence["integrityDigest"] == row["expected"]["sign"]["evidence"]["integrityDigest"]
    cases = row["input"]["verifyCases"]
    expected = row["expected"]["verify"]
    for label, case in cases.items():
        if label == "tamperedValue":
            target = {"a": "y", "b": [1, 2]}
            got = verify_controlled_integrity(target, key, key_id, cases["valid"])
        else:
            got = verify_controlled_integrity(value, key, key_id, case)
        assert got is expected[label]


def check_audit_valid(row):
    key = row["input"]["signingKeyUtf8"]
    receipt = row["input"]["receipt"]
    assert verify_audit_receipt(receipt, key) is row["expected"]["result"]
    document = copy.deepcopy(receipt)
    del document["integrity"]["signature"]
    assert stable_hash(document) == row["expected"]["macInputAscii"]
    restamped = resign_audit_receipt(receipt, key)
    assert restamped["integrity"]["signature"] == receipt["integrity"]["signature"]


def check_audit_failures(row, catalog):
    key = catalog["v1_key"]
    receipt = catalog["v1_receipt"]
    expected = row["expected"]
    tampered = copy.deepcopy(receipt)
    tampered["outcome"] = "allowed"
    assert verify_audit_receipt(tampered, key) is expected["tamperedOutcome"]
    assert (
        verify_audit_receipt(receipt, "synthetic-audit-key-WRONG-0000000") is expected["wrongKey"]
    )
    upper = copy.deepcopy(receipt)
    upper["integrity"]["signature"] = upper["integrity"]["signature"].upper()
    assert verify_audit_receipt(upper, key) is expected["uppercaseSignature"]
    marked = copy.deepcopy(receipt)
    marked["authorityPolicyVersion"] = "2"
    assert (
        verify_audit_receipt(resign_audit_receipt(marked, key), key)
        is expected["v2DiscriminatorResigned"]
    )
    assert verify_audit_receipt(None, key) is expected["nullReceipt"]
    missing = copy.deepcopy(receipt)
    del missing["integrity"]
    assert verify_audit_receipt(missing, key) is expected["missingIntegrity"]


def check_keyid_swap(row, catalog):
    receipt = copy.deepcopy(catalog["v1_receipt"])
    key = catalog["v1_key"]
    swapped = copy.deepcopy(receipt)
    swapped["integrity"]["keyId"] = "synthetic-key-b"
    assert verify_audit_receipt(swapped, key) is row["expected"]["swappedKeyIdOldSignature"]
    assert verify_audit_receipt(receipt, key) is row["expected"]["control_unchanged"]


def check_v1_hash_mismatch(row, catalog):
    key = catalog["v1_key"]
    mismatched = copy.deepcopy(catalog["v1_receipt"])
    mismatched["artifacts"]["request"]["hash"] = "0" * 64
    mismatched = resign_audit_receipt(mismatched, key)
    assert verify_audit_receipt(mismatched, key) is row["expected"]["mismatchReMaced"]
    control = resign_audit_receipt(catalog["v1_receipt"], key)
    assert verify_audit_receipt(control, key) is row["expected"]["control_reMacedUnchanged"]


def check_key_encoding(row, catalog):
    key = catalog["v1_key"]
    expected = row["expected"]
    assert verify_audit_receipt(catalog["v1_receipt"], key.encode("utf-8")) is expected[
        "keyAsUtf8Bytes"
    ]
    short = "short"
    resigned = resign_audit_receipt(catalog["v1_receipt"], short)
    assert verify_audit_receipt(resigned, short) is expected["fiveCharKey"]
    try:
        audit_signing_key(short)
    except TypeError as err:
        assert str(err) == expected["runtimeRejectsShortKey"]["error"]["message"]
    else:
        raise AssertionError("runtimeRejectsShortKey accepted")
    eight = "é" * 8
    try:
        audit_signing_key(eight)
    except TypeError as err:
        assert str(err) == expected["runtimeEightNonAsciiChars"]["error"]["message"]
    else:
        raise AssertionError("runtimeEightNonAsciiChars accepted")
    controlled_signing_key(eight)
    try:
        controlled_signing_key(b"a" * 15)
    except ValueError as err:
        assert str(err) == expected["controlledFifteenByteKey"]["error"]["message"]
    else:
        raise AssertionError("controlledFifteenByteKey accepted")


def check_linkage(row, catalog):
    expected = row["expected"]
    key = catalog["v2_key"]
    assert verify_audit_receipt(catalog["v2_allowed"], key) is expected["v2AllowedReceipt"]
    assert verify_audit_receipt(catalog["v2_denied"], key) is expected["v2DeniedReceipt"]
    for label, want in expected["v2Mutations"].items():
        mutated = apply_v2_mutation(catalog["v2_allowed"], label)
        got = verify_audit_receipt(resign_audit_receipt(mutated, key), key)
        assert got is want, f"v2 {label} {got} != {want}"
    v1_key = catalog["v1_key"]
    for label, want in expected["v1Mutations"].items():
        mutated = apply_v1_mutation(catalog["v1_receipt"], label)
        got = verify_audit_receipt(resign_audit_receipt(mutated, v1_key), v1_key)
        assert got is want, f"v1 {label} {got} != {want}"


def check_restamp(row):
    expected = row["expected"]
    for label in ("v1", "v2"):
        case = row["input"][label]
        key = case["signingKeyUtf8"]
        receipt = case["receipt"]
        assert verify_audit_receipt(receipt, key) is expected[f"{label}AsIssued"]
        restamped = resign_audit_receipt(receipt, key)
        assert verify_audit_receipt(restamped, key) is expected[f"{label}Restamped"]
        assert restamped["integrity"]["signature"] == expected[f"{label}RestampedSignature"]


def apply_v2_mutation(receipt, label):
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
    raise AssertionError(f"unknown v2 mutation {label}")


def apply_v1_mutation(receipt, label):
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
    raise AssertionError(f"unknown v1 mutation {label}")


def refresh_hashes(receipt):
    for entry in receipt["artifacts"].values():
        entry["hash"] = stable_hash(entry["value"])
    return receipt
