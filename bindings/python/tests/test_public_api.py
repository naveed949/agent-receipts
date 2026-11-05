import inspect
from datetime import datetime

import pytest

import agent_receipts as m
from agent_receipts import CanonicalizeError


FUNCTIONS = {
    "canonical_json": ("value",),
    "stable_hash": ("value",),
    "verify_audit_receipt": ("receipt", "key"),
    "resign_audit_receipt": ("receipt", "key"),
    "verify_controlled_integrity": ("value", "key", "key_id", "evidence"),
    "sign_controlled_integrity": ("value", "key", "key_id"),
    "audit_signing_key": ("key",),
    "controlled_signing_key": ("key",),
    "compare_authority_contracts": ("previous", "next"),
    "normalize_authority_policy": ("value",),
    "normalize_https_authority_rules": ("value",),
    "is_https_authority_subset": ("inner", "outer"),
}

CONSTANTS = {
    "AUDIT_RECEIPT_VERSION",
    "AUDIT_RECEIPT_V2_VERSION",
    "CONTROLLED_INTEGRITY_VERSION",
}

COMPARE_KEYS = {"relationship", "widened", "narrowed"}


def pin_parameters(signature, names):
    params = tuple(signature.parameters.values())
    assert tuple(param.name for param in params) == names
    for param in params:
        assert param.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD, (
            param.name,
            param.kind,
        )
        assert param.default is inspect.Parameter.empty, (param.name, param.default)


def pin_compare_keys(got):
    assert set(got) == COMPARE_KEYS
    assert isinstance(got["relationship"], str)
    assert isinstance(got["widened"], list)
    assert isinstance(got["narrowed"], list)


def observe_code(code, exc, call):
    with pytest.raises(exc) as caught:
        call()
    assert getattr(caught.value, "code", None) == code, (
        code,
        type(caught.value).__name__,
        caught.value,
    )


def pin_signer(call, exc, message):
    with pytest.raises(exc) as caught:
        call()
    err = caught.value
    assert str(err) == message
    assert getattr(err, "code", None) is None


def nested_lists(depth):
    value = None
    for _ in range(depth):
        value = [value]
    return value


def cycle_list():
    value = []
    value.append(value)
    return value


def https_rule(**overrides):
    rule = {
        "protocol": "https",
        "host": "api.example.com",
        "port": 443,
        "methods": ["GET"],
        "resolution": "public-only",
        "redirects": "none",
        "maxResponseBytes": 1024,
        "timeoutMs": 1000,
    }
    rule.update(overrides)
    return {"version": "2", "network": {"https": [rule]}}


def test_exported_names():
    names = {
        name
        for name in dir(m)
        if not name.startswith("_") and name != m.__name__
    }
    assert names == set(FUNCTIONS) | CONSTANTS | {"CanonicalizeError"}


def test_function_signatures():
    for name, params in FUNCTIONS.items():
        pin_parameters(inspect.signature(getattr(m, name)), params)


def test_compare_result_keys():
    got = m.compare_authority_contracts(
        {"filesystem": {"read": ["a"]}},
        {"filesystem": {"read": ["a", "b"]}},
    )
    pin_compare_keys(got)


def test_canonicalize_error_codes():
    cases = (
        ("type_error", lambda: m.canonical_json(object())),
        ("not_utf8", lambda: m.canonical_json(b"\xff")),
        ("invalid_json", lambda: m.canonical_json(b"{")),
        ("too_deep", lambda: m.canonical_json(nested_lists(129))),
        ("cycle", lambda: m.canonical_json(cycle_list())),
    )
    for code, call in cases:
        observe_code(code, CanonicalizeError, call)


def test_authority_error_codes():
    cases = (
        ("not_an_object", lambda: m.compare_authority_contracts([], {})),
        ("cross_version", lambda: m.compare_authority_contracts({}, {"version": "2"})),
        (
            "unsupported_version",
            lambda: m.compare_authority_contracts({"version": "3"}, {"version": "3"}),
        ),
        (
            "unknown_field",
            lambda: m.compare_authority_contracts(
                {"filesystem": {"read": []}},
                {"filesystem": {"read": [], "exec": ["x"]}},
            ),
        ),
        (
            "https_in_v1",
            lambda: m.compare_authority_contracts({}, {"network": {"https": []}}),
        ),
        (
            "outbound_in_v2",
            lambda: m.compare_authority_contracts(
                {"version": "2"},
                {"version": "2", "network": {"outbound": "any"}},
            ),
        ),
        (
            "invalid_scope",
            lambda: m.compare_authority_contracts({"git": {"write": [" padded"]}}, {}),
        ),
        (
            "invalid_flag",
            lambda: m.compare_authority_contracts(
                {"output": {"unrestricted": "yes"}},
                {},
            ),
        ),
        (
            "invalid_https_host",
            lambda: m.compare_authority_contracts(
                https_rule(host="127.0.0.1"),
                {"version": "2"},
            ),
        ),
        (
            "invalid_https_port",
            lambda: m.compare_authority_contracts(
                https_rule(port=0),
                {"version": "2"},
            ),
        ),
        (
            "invalid_https_method",
            lambda: m.compare_authority_contracts(
                https_rule(methods=["get"]),
                {"version": "2"},
            ),
        ),
        (
            "invalid_https_bounds",
            lambda: m.compare_authority_contracts(
                https_rule(maxResponseBytes=0),
                {"version": "2"},
            ),
        ),
        (
            "invalid_https_shape",
            lambda: m.compare_authority_contracts(
                {"version": "2", "network": {"https": False}},
                {"version": "2"},
            ),
        ),
    )
    for code, call in cases:
        observe_code(code, TypeError, call)


def test_host_conversion_type_error():
    observe_code(
        "type_error",
        TypeError,
        lambda: m.compare_authority_contracts(datetime(2020, 1, 1), {}),
    )


def test_signer_errors():
    pin_signer(
        lambda: m.audit_signing_key(b"short"),
        TypeError,
        "audit signingKey must contain at least 16 bytes",
    )
    pin_signer(
        lambda: m.controlled_signing_key(b"a" * 15),
        ValueError,
        "controlled integrity signing key must contain at least 16 bytes",
    )
    pin_signer(
        lambda: m.sign_controlled_integrity({}, b"0123456789abcdef", ""),
        ValueError,
        "invalid key id",
    )
