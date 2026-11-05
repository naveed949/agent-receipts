# Python abi3 wheel

The Python binding ships as one `cp39-abi3` wheel built by maturin, then pytest runs against that installed wheel. GitHub Actions builds that wheel on linux x86_64 and aarch64, uploads it as `agent-receipts-cp39-abi3-<arch>`, and installs it into a clean venv on CPython 3.9 and 3.13. Local `verify.sh` installs the same wheel into `$EVIDENCE/venv` when `python3 -m venv` works, otherwise into `python3 --user`.

## Sub-features

- `py-build` builds `bindings/python` with `maturin==1.16.0` for `python3`.
- `py-wheel` deletes stale `*cp39-abi3*.whl` files, then installs the wheel path maturin reports for this build.
- `py-pytest` runs `bindings/python/tests` on the installed module, including the public-API inspect tests and the shared vectors.
- `py-toolchain` fails closed when Python 3.9+, pip, maturin, or pytest cannot run.
- `py-ci-venv` is the Actions path: a clean venv on 3.9 and a clean venv on 3.13, each installing the same `cp39-abi3` wheel. Local verify does not require both CPythons.

## How to get to it (user POV)

- From the repository root, run the commands in the README Python section.
- Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. That path parses the wheel path maturin prints. It does not glob `target/wheels/*cp39-abi3*.whl`.

## Driving it with verify.sh

Preconditions:

- `python3` is 3.9 or later.
- `scripts/verify.sh doctor` prints `RESULT=PASS`.

- **Install tools.** Run `.cursor/skills/verify-agent-receipts/scripts/verify.sh`. The script installs `maturin==1.16.0` and `pytest`.
- **Build and test.** The `python-abi3` row is `PASS`. `python-abi3.log` contains the maturin build, a pip install of the wheel path printed by that build, and a pytest run that exited 0.
- **Missing tool.** If Python or pip is missing, or maturin cannot install, the row is `FAIL`. It is not `UNSUPPORTED` and not `PASS`.
- **Missing wheel path.** If maturin stdout has no absolute path containing `cp39-abi3` and ending in `.whl`, or that path is not a file, the row is `FAIL`.

## Gotchas

- `maturin develop` links a dev module. That is not this surface.
- The wheel name contains `cp39-abi3` even on Python 3.12. Do not glob `*cp312*`.
- Pytest must import `agent_receipts` from the installed wheel, not from a source tree of `.py` files. This crate is a cdylib.
- An inherited `CARGO_TARGET_DIR` is unset and replaced with this checkout's `target/`. Do not install a wheel from another tree.
