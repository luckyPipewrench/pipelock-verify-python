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
from cryptography.exceptions import UnsupportedAlgorithm

import pipelock_verify
import pipelock_verify._rotation as rotation_module

CONFORMANCE_DIR = Path(__file__).parent / "conformance"
FIXTURE_DIR = Path(__file__).parent / "fixtures"


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


def test_rotated_chain_verifies_from_one_root_plus_endorsement(test_key_hex):
    endorsement = pipelock_verify.load_rotation_endorsement(
        CONFORMANCE_DIR / "g1-rotation-endorsement.json"
    )
    result = pipelock_verify.verify_chain(
        CONFORMANCE_DIR / "g1-rotated-close-count-valid.jsonl",
        public_key_hex=test_key_hex,
        session_id="conformance-session",
        rotation_endorsements=[endorsement],
    )
    assert result.valid, result.error
    assert result.receipt_count == 6
    assert result.final_seq == 2


def test_twice_rotated_chain_verifies_from_one_root_plus_both_endorsements(
    test_key_hex,
):
    endorsements = [
        pipelock_verify.load_rotation_endorsement(CONFORMANCE_DIR / "g1-rotation-endorsement.json"),
        pipelock_verify.load_rotation_endorsement(
            CONFORMANCE_DIR / "g1-rotation-endorsement-2.json"
        ),
    ]
    result = pipelock_verify.verify_chain(
        CONFORMANCE_DIR / "g1-rotated-twice-valid.jsonl",
        public_key_hex=test_key_hex,
        session_id="conformance-session",
        rotation_endorsements=endorsements,
    )
    assert result.valid, result.error
    assert result.receipt_count == 9


def test_rotation_endorsement_trust_fails_closed(test_key_hex):
    path = CONFORMANCE_DIR / "g1-rotated-close-count-valid.jsonl"
    endorsement = pipelock_verify.load_rotation_endorsement(
        CONFORMANCE_DIR / "g1-rotation-endorsement.json"
    )

    missing = pipelock_verify.verify_chain(
        path,
        public_key_hex=test_key_hex,
        session_id="conformance-session",
    )
    assert not missing.valid
    assert "does not match receipt boundary" in (missing.error or "")

    altered = {
        **vars(endorsement),
        "prior_tail_hash": "0" * 64,
    }
    with pytest.raises(
        pipelock_verify.InvalidReceiptError,
        match="signature verification failed",
    ):
        pipelock_verify.verify_rotation_endorsement(altered)
    with pytest.raises(
        pipelock_verify.InvalidReceiptError,
        match="canonical UTC RFC3339Nano",
    ):
        pipelock_verify.verify_rotation_endorsement(
            {
                **vars(endorsement),
                "rotated_at": "2026-02-30T12:00:00Z",
            }
        )

    duplicate = pipelock_verify.verify_chain(
        path,
        public_key_hex=test_key_hex,
        session_id="conformance-session",
        rotation_endorsements=[endorsement, endorsement],
    )
    assert not duplicate.valid
    assert "multiple rotation endorsements" in (duplicate.error or "")

    second = pipelock_verify.load_rotation_endorsement(
        CONFORMANCE_DIR / "g1-rotation-endorsement-2.json"
    )
    replayed = pipelock_verify.verify_chain(
        path,
        public_key_hex=test_key_hex,
        session_id="conformance-session",
        rotation_endorsements=[endorsement, second],
    )
    assert not replayed.valid
    assert "unused rotation endorsement" in (replayed.error or "")

    cross_session = pipelock_verify.verify_chain(
        path,
        public_key_hex=test_key_hex,
        session_id="other-session",
        rotation_endorsements=[endorsement],
    )
    assert not cross_session.valid
    assert "signed recorder session" in (cross_session.error or "")


@pytest.mark.parametrize("failure", [ValueError("bad key"), UnsupportedAlgorithm("unsupported")])
def test_rotation_endorsement_wraps_signer_key_load_failures(monkeypatch, failure):
    endorsement = json.loads((CONFORMANCE_DIR / "g1-rotation-endorsement.json").read_text())

    class FailingPublicKey:
        @staticmethod
        def from_public_bytes(_key):
            raise failure

    monkeypatch.setattr(rotation_module, "Ed25519PublicKey", FailingPublicKey)
    with pytest.raises(
        pipelock_verify.InvalidReceiptError,
        match="rotation endorsement signer key is invalid",
    ):
        pipelock_verify.verify_rotation_endorsement(endorsement)


def test_rotation_endorsement_file_rejects_duplicate_unknown_and_trailing_fields(
    tmp_path,
):
    source = (CONFORMANCE_DIR / "g1-rotation-endorsement.json").read_text().strip()
    cases = [
        (
            source.replace('"version": 1,', '"version": 1, "version": 1,'),
            "duplicate object key",
        ),
        (
            source.replace("\n}", ',\n  "trusted": true\n}'),
            "unknown field trusted",
        ),
        (f"{source}\n{{}}", "unmarshal rotation endorsement"),
    ]
    for index, (body, error) in enumerate(cases):
        path = tmp_path / f"bad-{index}.json"
        path.write_text(body)
        with pytest.raises(pipelock_verify.InvalidReceiptError, match=error):
            pipelock_verify.load_rotation_endorsement(path)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * (64 * 1024))
    with pytest.raises(pipelock_verify.InvalidReceiptError, match="exceeds 65536 bytes"):
        pipelock_verify.load_rotation_endorsement(oversized)


def test_v3_2_0_live_recorder_chain_verifies_with_pinned_key():
    """A real v3.2.0 recorder log must verify end-to-end.

    This fixture carries action_receipt entries with decision_phase,
    run_nonce, session_open/heartbeat/session_close controls, interleaved with
    evidence_receipt, checkpoint, and transcript_root entries. It is the
    regression gate for drift from Go's frozen v1 canonical projection in
    internal/receipt/canonical.go.
    """
    public_key = (FIXTURE_DIR / "v3_2_0_live_chain.pub").read_text().strip()
    result = pipelock_verify.verify_chain(
        FIXTURE_DIR / "v3_2_0_live_chain.jsonl",
        public_key_hex=public_key,
    )
    assert result.valid, f"live v3.2.0 chain invalid: {result.error}"
    assert result.receipt_count == 11
    assert result.final_seq == 10
    assert result.start_time == "2026-07-24T22:57:41.86819273Z"
    assert result.end_time == "2026-07-24T23:00:44.292030929Z"
    # Pinned to the root hash the Go verifier independently computed for this
    # exact chain (pipelock v3.2.0 `verify-receipt --chain`). Validity alone
    # would not catch a divergence in the chain-hash construction: both
    # verifiers can agree a chain is well formed while disagreeing on what it
    # commits to. This is the parity assertion.
    assert result.root_hash == "623d13a756891c52b6a4b3d400a95c3324da7b5c3b11c95446fb11aee2ea3063"
