import inspect

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

ERROR_CODES = {
    "not_utf8",
    "invalid_json",
    "too_deep",
    "cycle",
    "type_error",
}


def test_exported_names():
    names = {
        name
        for name in dir(m)
        if not name.startswith("_") and name != m.__name__
    }
    assert names == set(FUNCTIONS) | CONSTANTS | {"CanonicalizeError"}


def test_function_signatures():
    for name, params in FUNCTIONS.items():
        signature = inspect.signature(getattr(m, name))
        assert tuple(signature.parameters) == params, name


def test_canonicalize_error_code():
    try:
        m.canonical_json(object())
    except CanonicalizeError as err:
        assert err.code in ERROR_CODES
        assert err.code == "type_error"
    else:
        raise AssertionError("expected CanonicalizeError")
