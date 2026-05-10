"""Atheris fuzz target for receipt parsing and verification paths.

The target intentionally ignores verifier outcomes: invalid receipts are expected.
It only treats uncaught exceptions as findings.
"""

from __future__ import annotations

import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

with atheris.instrument_imports():
    import pipelock_verify


def TestOneInput(data: bytes) -> None:
    if len(data) > 16384:
        data = data[:16384]

    try:
        text = data.decode("utf-8", errors="ignore")
        pipelock_verify.verify(text)
    except (MemoryError, RecursionError):
        raise
    except Exception:
        # Malformed receipts, bad JSON, bad signatures, and unsupported shapes
        # are expected corpus cases. The fuzzer is looking for crashes.
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
