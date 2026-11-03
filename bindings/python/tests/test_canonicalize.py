import base64
import json
from pathlib import Path

import pytest

import agent_receipts

VECTORS = Path(__file__).resolve().parents[3] / "vectors" / "canonicalize"


def vector_paths():
    return sorted(VECTORS.glob("*.json"))


def test_vector_directory_is_not_empty():
    assert vector_paths(), "vectors/canonicalize is empty"


@pytest.mark.parametrize("path", vector_paths(), ids=lambda path: path.name)
def test_canonicalize_vector(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    keys = set(data)
    raw = decode_field(data["input_b64"])
    if keys == {"input_b64", "output_b64"}:
        expected = decode_field(data["output_b64"])
        got = agent_receipts.canonicalize_bytes(raw)
        assert type(got) is bytes
        assert got == expected
        again = agent_receipts.canonicalize_bytes(got)
        assert type(again) is bytes
        assert again == got
        return
    if keys == {"input_b64", "error"}:
        with pytest.raises(agent_receipts.CanonicalizeError) as caught:
            agent_receipts.canonicalize_bytes(raw)
        assert caught.value.code == data["error"]
        return
    raise AssertionError(f"illegal keys in {path.name}: {sorted(keys)}")


def test_str_is_type_error():
    with pytest.raises(TypeError):
        agent_receipts.canonicalize_bytes('{"a": 1}')


def decode_field(field):
    raw = base64.standard_b64decode(field)
    encoded = base64.standard_b64encode(raw).decode("ascii")
    assert encoded == field
    return raw
