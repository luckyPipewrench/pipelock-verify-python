"""Golden-file tests: Python must agree with Go on every conformance fixture.

The fixtures in ``tests/conformance/`` are bit-identical copies of the files
Go generates in ``pipelock/sdk/conformance/testdata/``. If either side
changes its canonicalization, serialization, or verification rules, this
test breaks — which is the point.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import pipelock_verify

CONFORMANCE_DIR = Path(__file__).parent / "conformance"


@pytest.fixture(scope="module")
def test_key_hex() -> str:
    with (CONFORMANCE_DIR / "test-key.json").open() as f:
        return json.load(f)["public_key_hex"]


def test_test_key_is_committed():
    """Sanity check: the fixture key file exists and has the expected shape."""
    key_file = CONFORMANCE_DIR / "test-key.json"
    assert key_file.exists(), f"missing fixture: {key_file}"
    data = json.loads(key_file.read_text())
    assert data["seed_phrase"] == "pipelock-conformance-test-key-v1"
    assert len(data["public_key_hex"]) == 64  # 32 bytes hex
    assert len(data["seed_hex"]) == 64


def test_valid_single_verifies_without_key(test_key_hex):
    """valid-single.json verifies against its embedded signer_key."""
    data = (CONFORMANCE_DIR / "valid-single.json").read_bytes()
    result = pipelock_verify.verify(data)
    assert result.valid, f"verification failed: {result.error}"
    assert result.signer_key == test_key_hex
    assert result.action_id == "conformance-00000"
    assert result.verdict == "allow"
    assert result.chain_seq == 0
    assert result.chain_prev_hash == "genesis"


def test_valid_single_verifies_with_pinned_key(test_key_hex):
    """valid-single.json verifies when we pin the expected key."""
    data = (CONFORMANCE_DIR / "valid-single.json").read_bytes()
    result = pipelock_verify.verify(data, public_key_hex=test_key_hex)
    assert result.valid, f"verification failed: {result.error}"


def test_valid_single_rejects_wrong_key():
    """valid-single.json fails when pinned to a key it wasn't signed with."""
    data = (CONFORMANCE_DIR / "valid-single.json").read_bytes()
    wrong_key = "00" * 32
    result = pipelock_verify.verify(data, public_key_hex=wrong_key)
    assert not result.valid
    assert result.error is not None
    assert "does not match expected key" in result.error


def test_valid_single_from_dict():
    """verify() accepts a pre-parsed dict, not just JSON bytes."""
    data = json.loads((CONFORMANCE_DIR / "valid-single.json").read_text())
    result = pipelock_verify.verify(data)
    assert result.valid, f"verification failed: {result.error}"


def test_valid_single_from_string():
    """verify() accepts a JSON string."""
    data = (CONFORMANCE_DIR / "valid-single.json").read_text()
    result = pipelock_verify.verify(data)
    assert result.valid, f"verification failed: {result.error}"


def test_invalid_signature_fails(test_key_hex):
    """invalid-signature.json has a flipped byte; verification must fail."""
    data = (CONFORMANCE_DIR / "invalid-signature.json").read_bytes()
    result = pipelock_verify.verify(data, public_key_hex=test_key_hex)
    assert not result.valid
    assert result.error is not None
    assert "signature verification failed" in result.error


def test_valid_chain_verifies(test_key_hex):
    """valid-chain.jsonl verifies end-to-end as a five-receipt chain."""
    path = CONFORMANCE_DIR / "valid-chain.jsonl"
    result = pipelock_verify.verify_chain(path, public_key_hex=test_key_hex)
    assert result.valid, f"chain invalid: {result.error}"
    assert result.receipt_count == 5
    assert result.final_seq == 4
    assert result.root_hash is not None
    assert len(result.root_hash) == 64  # 32-byte hex
    assert result.start_time == "2026-04-15T12:00:00Z"
    assert result.end_time == "2026-04-15T12:00:04Z"


def test_valid_chain_without_pinned_key():
    """verify_chain() auto-pins the first receipt's key when none supplied."""
    path = CONFORMANCE_DIR / "valid-chain.jsonl"
    result = pipelock_verify.verify_chain(path)
    assert result.valid, f"chain invalid: {result.error}"
    assert result.receipt_count == 5


def test_broken_chain_reports_correct_break(test_key_hex):
    """broken-chain.jsonl has a prev_hash break at seq 3, signatures valid."""
    path = CONFORMANCE_DIR / "broken-chain.jsonl"
    result = pipelock_verify.verify_chain(path, public_key_hex=test_key_hex)
    assert not result.valid
    assert result.broken_at_seq == 3
    assert result.error is not None
    assert "chain_prev_hash mismatch" in result.error


def test_broken_chain_individual_signatures_valid(test_key_hex):
    """Each receipt in broken-chain.jsonl still has a valid signature.

    The break is structural (prev_hash linkage), not cryptographic. A
    verifier that only checks individual signatures would say every
    receipt is fine — the chain-level check is what catches it.
    """
    path = CONFORMANCE_DIR / "broken-chain.jsonl"
    raw = path.read_text()
    for i, line in enumerate(raw.strip().split("\n")):
        result = pipelock_verify.verify(line, public_key_hex=test_key_hex)
        assert result.valid, f"receipt {i} sig invalid: {result.error}"
