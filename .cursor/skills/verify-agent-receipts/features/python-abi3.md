# Python abi3 wheel

The Python binding ships as one `cp39-abi3` wheel built by maturin, then pytest runs against that installed wheel.

## Sub-features

- `py-build` builds `bindings/python` with `maturin==1.16.0` for `python3`.
- `py-wheel` installs exactly one `*cp39-abi3*.whl` from `target/wheels`.
- `py-pytest` runs `bindings/python/tests` on the installed module.
- `py-toolchain` fails closed when Python 3.9+, pip, maturin, or pytest cannot run.

## How to get to it (user POV)

- From the repository root, run the commands in the README Python section.
- Run `scripts/verify.sh`, which runs those commands as the `python-abi3` surface.

## Driving it with verify.sh

Preconditions:

- `python3` is 3.9 or later.
- `scripts/verify.sh doctor` prints `RESULT=PASS`.

- **Install tools.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The script installs `maturin==1.16.0` and `pytest`.
- **Build and test.** The `python-abi3` row is `PASS`. `python-abi3.log` contains the maturin build, a pip install of one `cp39-abi3` wheel, and a pytest run that exited 0.
- **Missing tool.** If Python or pip is missing, or maturin cannot install, the row is `FAIL`. It is not `UNSUPPORTED` and not `PASS`.
- **Wrong wheel count.** If `target/wheels` does not contain exactly one `*cp39-abi3*.whl`, the row is `FAIL`.

## Gotchas

- `maturin develop` links a dev module. That is not this surface.
- The wheel name contains `cp39-abi3` even on Python 3.12. Do not glob `*cp312*`.
- Pytest must import `agent_receipts` from the installed wheel, not from a source tree of `.py` files. This crate is a cdylib.
