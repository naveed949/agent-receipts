import asyncio
import gc
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import agent_receipts as m

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "vectors" / "reference" / "vectors.json"


def v1_receipt():
    root = json.loads(VECTORS.read_text())
    for row in root["vectors"]:
        if row["name"] == "hmac-audit-receipt-valid":
            return row["input"]["receipt"], row["input"]["signingKeyUtf8"]
    raise AssertionError("missing hmac-audit-receipt-valid")


def write_jsonl(tmp_path):
    receipt, key = v1_receipt()
    body = m.canonical_json(receipt).encode("utf-8")
    path = tmp_path / "audit.jsonl"
    path.write_bytes(body + b"\n")
    return path, key, body


def test_verify_stream_identity(tmp_path):
    path, key, _body = write_jsonl(tmp_path)

    async def go():
        text = await m.verify_stream(str(path), key)
        raw = await m.verify_stream(str(path), key.encode("utf-8"))
        array = await m.verify_stream(str(path), bytearray(key.encode("utf-8")))
        return text, raw, array

    text, raw, array = asyncio.run(go())
    assert text == {"ok": 1, "invalid": 0, "malformed": 0}
    assert raw == text
    assert array == text


def test_short_key_still_returns_counts(tmp_path):
    path, _key, _body = write_jsonl(tmp_path)

    async def go():
        return await m.verify_stream(str(path), "short")

    counts = asyncio.run(go())
    assert counts == {"ok": 0, "invalid": 1, "malformed": 0}


def test_bad_key_type_is_type_error_before_awaitable():
    with pytest.raises(TypeError, match="key must be bytes, bytearray, or str"):
        m.verify_stream("unused", 1)


def test_bool_limit_is_type_error():
    with pytest.raises(TypeError):
        m.verify_stream("unused", b"k", capacity=True)
    with pytest.raises(TypeError):
        m.verify_stream("unused", b"k", max_line_len=False)


def test_zero_limit_is_value_error():
    with pytest.raises(ValueError, match="capacity must be greater than zero"):
        m.verify_stream("unused", b"k", capacity=0)
    with pytest.raises(ValueError, match="max_line_len must be greater than zero"):
        m.verify_stream("unused", b"k", max_line_len=0)


def test_limit_overflow():
    with pytest.raises(OverflowError):
        m.verify_stream("unused", b"k", capacity=2**128)


def test_non_utf8_path(tmp_path):
    receipt, key = v1_receipt()
    body = m.canonical_json(receipt).encode("utf-8") + b"\n"
    raw = os.path.join(os.fsencode(tmp_path), b"caf\xff.jsonl")
    fd = os.open(raw, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
    os.write(fd, body)
    os.close(fd)
    sur = os.fsdecode(raw)
    assert open(sur, "rb").read() == body

    async def go():
        via_str = await m.verify_stream(sur, key)
        via_bytes = await m.verify_stream(raw, key)

        class BytesLike:
            def __fspath__(self):
                return raw

        via_pathlike = await m.verify_stream(BytesLike(), key)
        return via_str, via_bytes, via_pathlike

    via_str, via_bytes, via_pathlike = asyncio.run(go())
    assert via_str == {"ok": 1, "invalid": 0, "malformed": 0}
    assert via_bytes == via_str
    assert via_pathlike == via_str


def test_python_del_leak(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    async def scenario():
        fut = m.verify_stream(str(fifo), b"k", capacity=1, max_line_len=8)
        writer = await asyncio.to_thread(os.open, fifo, os.O_WRONLY)
        await asyncio.sleep(0.05)
        del fut
        gc.collect()
        await asyncio.sleep(0.2)
        writes = []
        for _ in range(2):
            try:
                writes.append(("wrote", os.write(writer, b"abc")))
            except BrokenPipeError as err:
                writes.append(("epipe", err.errno))
            await asyncio.sleep(0.05)
        os.close(writer)
        return writes

    writes = asyncio.run(scenario())
    assert any(kind == "epipe" for kind, _ in writes), writes


def _child_exits_clean(script, repeats=8):
    for _ in range(repeats):
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        stderr = proc.stderr or ""
        assert proc.returncode == 0, (proc.returncode, proc.stdout, stderr)
        assert "FATAL" not in stderr
        assert "exception not rethrown" not in stderr
        assert "not initialized" not in stderr
        assert "panicked" not in stderr


def test_python_del_leak_exit():
    _child_exits_clean(
        "import asyncio\n"
        "import agent_receipts as m\n"
        "async def main():\n"
        '    fut = m.verify_stream("/dev/zero", b"k", max_line_len=8)\n'
        "    del fut\n"
        "asyncio.run(main())\n"
    )


def test_python_await_then_exit():
    _child_exits_clean(
        "import asyncio\n"
        "import agent_receipts as m\n"
        "async def main():\n"
        '    fut = m.verify_stream("/dev/zero", b"k", max_line_len=8)\n'
        "    it = fut.__await__()\n"
        "    del it\n"
        "    del fut\n"
        "asyncio.run(main())\n"
    )


def test_python_wait_for_timeout_exit():
    _child_exits_clean(
        "import asyncio\n"
        "import agent_receipts as m\n"
        "async def main():\n"
        "    try:\n"
        '        await asyncio.wait_for(m.verify_stream("/dev/zero", b"k", max_line_len=8), 0.01)\n'
        "    except (asyncio.TimeoutError, asyncio.CancelledError):\n"
        "        pass\n"
        "asyncio.run(main())\n"
    )


def test_python_gather_cancel_exit():
    _child_exits_clean(
        "import asyncio\n"
        "import agent_receipts as m\n"
        "async def main():\n"
        "    async def both():\n"
        "        return await asyncio.gather(\n"
        '            m.verify_stream("/dev/zero", b"k", max_line_len=8),\n'
        "            asyncio.Event().wait(),\n"
        "        )\n"
        "    task = asyncio.create_task(both())\n"
        "    await asyncio.sleep(0.01)\n"
        "    task.cancel()\n"
        "    try:\n"
        "        await task\n"
        "    except asyncio.CancelledError:\n"
        "        pass\n"
        "asyncio.run(main())\n"
    )


def test_stream_limits_panic():
    with pytest.raises(ValueError, match="capacity exceeds the channel permit limit"):
        m.verify_stream("unused", b"k", capacity=(1 << 64) - 1)
    with pytest.raises(ValueError, match="retained line bytes overflowed usize"):
        m.verify_stream("unused", b"k", max_line_len=(1 << 64) - 1)


def test_limits_are_keyword_only(tmp_path):
    path, key, _body = write_jsonl(tmp_path)
    with pytest.raises(TypeError):
        m.verify_stream(str(path), key, 4)


def test_call_returns_awaitable(tmp_path):
    path, key, _body = write_jsonl(tmp_path)

    async def go():
        got = m.verify_stream(str(path), key)
        assert inspect.isawaitable(got)
        return await got

    assert asyncio.run(go())["ok"] == 1


def test_pathlike_and_truncated_receipt(tmp_path):
    path, key, body = write_jsonl(tmp_path)

    class PathLike:
        def __fspath__(self):
            return str(path)

    async def go():
        ok = await m.verify_stream(PathLike(), key)
        path.write_bytes(body)
        truncated = await m.verify_stream(path, key)
        return ok, truncated

    ok, truncated = asyncio.run(go())
    assert ok["ok"] == 1
    assert truncated == {"ok": 0, "invalid": 0, "malformed": 1}


def test_extra_field_and_foreign_object(tmp_path):
    receipt, key = v1_receipt()
    extra = dict(receipt)
    extra["zzz_extra"] = True
    path = tmp_path / "mix.jsonl"
    extra_line = m.canonical_json(extra).encode("utf-8")
    path.write_bytes(extra_line + b"\n" + b'{"foo":1,"bar":2}\n \t\n\n')

    async def go():
        return await m.verify_stream(str(path), key)

    counts = asyncio.run(go())
    assert counts == {"ok": 0, "invalid": 0, "malformed": 4}


def test_malformed_oversized_and_truncated(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_bytes(b"0123456789abcdef\n" + b'{"a":1}')

    async def go():
        return await m.verify_stream(str(path), b"k", capacity=2, max_line_len=8)

    assert asyncio.run(go()) == {"ok": 0, "invalid": 0, "malformed": 2}


def test_missing_file_is_os_error(tmp_path):
    async def go():
        await m.verify_stream(str(tmp_path / "nope.jsonl"), b"k")

    with pytest.raises(OSError):
        asyncio.run(go())


def test_gather_cancel_returns_no_dict(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    async def scenario():
        async def both():
            return await asyncio.gather(
                m.verify_stream(str(fifo), b"k"),
                asyncio.Event().wait(),
            )

        task = asyncio.create_task(both())
        writer = await asyncio.to_thread(os.open, fifo, os.O_WRONLY)
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            got = await task
        except asyncio.CancelledError:
            got = None
        os.close(writer)
        return got

    assert asyncio.run(scenario()) is None
