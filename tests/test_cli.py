"""CLI integration tests for ``python -m pipelock_verify``."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipelock_verify.__main__ import main

CONFORMANCE_DIR = Path(__file__).parent / "conformance"


def test_cli_single_valid(capsys):
    exit_code = main([str(CONFORMANCE_DIR / "valid-single.json")])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "OK:" in captured.out
    assert "conformance-00000" in captured.out


def test_cli_single_invalid(capsys):
    exit_code = main([str(CONFORMANCE_DIR / "invalid-signature.json")])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "FAILED:" in captured.out
    assert "signature verification failed" in captured.out


def test_cli_chain_valid(capsys):
    exit_code = main([str(CONFORMANCE_DIR / "valid-chain.jsonl")])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "CHAIN VALID:" in captured.out
    assert "Receipts:  5" in captured.out
    assert "Final seq: 4" in captured.out


def test_cli_chain_broken(capsys):
    exit_code = main([str(CONFORMANCE_DIR / "broken-chain.jsonl")])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "CHAIN BROKEN:" in captured.out
    assert "seq 3" in captured.out


def test_cli_wrong_key(capsys):
    """Pinning a different key must fail even a structurally-valid receipt."""
    wrong_key = "00" * 32
    exit_code = main([str(CONFORMANCE_DIR / "valid-single.json"), "--key", wrong_key])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "does not match expected key" in captured.out


def test_cli_missing_file(capsys):
    exit_code = main([str(CONFORMANCE_DIR / "does-not-exist.json")])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "file not found" in captured.err


def test_cli_mode_override(capsys):
    """--mode forces chain parsing even on a non-jsonl extension."""
    # valid-single.json is a single receipt but we can ask for single mode.
    exit_code = main([str(CONFORMANCE_DIR / "valid-single.json"), "--mode", "single"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "OK:" in captured.out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "pipelock-verify" in captured.out
