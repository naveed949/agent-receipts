import base64
import json
import math
from datetime import datetime
from pathlib import Path

import pytest

from agent_receipts import CanonicalizeError, canonical_json, stable_hash

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


def test_reference_vectors(capsys):
    failures = []
    root = load_reference()
    allow = read_allowlist(REFERENCE / "pending-kinds.txt")
    count = root["count"]
    rows = root["vectors"]
    if count != len(rows) or len(rows) != 20:
        failures.append(f"count {count} len {len(rows)}")
        rows = []

    pending_lines = []
    seen = []
    canonical_ok = 0
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
        canonical_ok != 8 or len(pending_lines) != 12 or canonical_ok + len(pending_lines) != 20
    ):
        failures.append(f"counts canonicalize {canonical_ok} pending {len(pending_lines)}")
    for line in pending_lines:
        print(line)
    print(f"pending {len(pending_lines)}")
    print(f"canonicalize {canonical_ok} ok")
    captured = capsys.readouterr().out
    for line in pending_lines:
        assert line in captured
    assert f"pending {len(pending_lines)}\n" in captured
    assert f"canonicalize {canonical_ok} ok\n" in captured
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
    value = None
    for _ in range(depth):
        value = [value]
    return value
