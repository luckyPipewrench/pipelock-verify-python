"""Regressions for review findings on 2026-04-09.

Each test reproduces a concrete divergence from the Go reference that the
original implementation missed. The goal is a red test first, then the fix,
so these exact failure modes can never quietly come back.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import pipelock_verify
from pipelock_verify.__main__ import main
from pipelock_verify._canonical import canonicalize_action_record

CONFORMANCE_DIR = Path(__file__).parent / "conformance"


def _load_test_key() -> tuple[str, str]:
    with (CONFORMANCE_DIR / "test-key.json").open() as f:
        info = json.load(f)
    return info["seed_hex"], info["public_key_hex"]


def _sign_action_record(ar: dict) -> dict:
    """Build a fully-signed receipt envelope from an action_record dict.

    Uses the conformance test key so existing key-pinning tests still apply.
    """
    seed_hex, public_key_hex = _load_test_key()
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))

    canonical = canonicalize_action_record(ar)
    import hashlib

    digest = hashlib.sha256(canonical).digest()
    sig = priv.sign(digest)

    return {
        "version": 1,
        "action_record": ar,
        "signature": "ed25519:" + sig.hex(),
        "signer_key": public_key_hex,
    }


def _valid_action_record() -> dict:
    return {
        "version": 1,
        "action_id": "regression-000",
        "action_type": "read",
        "timestamp": "2026-04-09T13:50:00Z",
        "principal": "org:test",
        "actor": "agent:test",
        "delegation_chain": ["grant"],
        "target": "https://example.com",
        "side_effect_class": "external_read",
        "reversibility": "reversible",
        "policy_hash": "",
        "verdict": "allow",
        "transport": "https",
        "chain_prev_hash": "genesis",
        "chain_seq": 0,
    }


# --- Finding 1: action_type enum enforcement ---


def test_bogus_action_type_rejected_even_when_signature_valid():
    """A receipt signed with a valid key but action_type "bogus" must fail.

    Before the fix, Python accepted this because it only checked presence,
    not enum membership. Go's ValidActionType rejects it at action.go:161.
    """
    ar = _valid_action_record()
    ar["action_type"] = "bogus"
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify(json.dumps(receipt))
    assert not result.valid
    assert result.error is not None
    assert "action_type" in result.error
    assert "bogus" in result.error


@pytest.mark.parametrize(
    "valid_type",
    [
        "read",
        "derive",
        "write",
        "delegate",
        "authorize",
        "spend",
        "commit",
        "actuate",
        "unclassified",
    ],
)
def test_all_nine_go_action_types_accepted(valid_type):
    """Every action type in Go's allActionTypes map must still verify."""
    ar = _valid_action_record()
    ar["action_type"] = valid_type
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify(json.dumps(receipt))
    assert result.valid, f"{valid_type}: {result.error}"


def test_empty_action_type_rejected_with_go_aligned_error():
    """Empty action_type must be rejected with the same wording Go uses.

    Go's Validate() in action.go:169 produces ``invalid action_type ""``
    (not ``action_type is required``) because ValidActionType returns false
    for the empty string and the required-field sweep never covers it.
    The Python verifier routes through the same enum branch so operators
    looking at a failure see the same diagnostic regardless of which
    verifier caught it.
    """
    ar = _valid_action_record()
    ar["action_type"] = ""
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify(json.dumps(receipt))
    assert not result.valid
    assert result.error == 'invalid action record: invalid action_type ""'


# --- Finding 1b: timestamp syntactic validation ---


def test_bogus_timestamp_rejected_with_valid_signature():
    """A receipt signed over a canonically-serialized action record with
    ``timestamp: "not-a-time"`` MUST be rejected. Go rejects this at
    json.Unmarshal before it ever reaches Verify(); Python parses into a
    dict, so the check has to be reproduced in _verify_receipt_dict or an
    attacker can ship garbage timestamps past the signature check."""
    ar = _valid_action_record()
    ar["timestamp"] = "not-a-time"
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify(json.dumps(receipt))
    assert not result.valid
    assert result.error is not None
    assert "timestamp" in result.error.lower()
    assert "not-a-time" in result.error


@pytest.mark.parametrize(
    "bad",
    [
        "2026-04-09",  # date only
        "2026-04-09T12:00:00",  # missing timezone
        "2026-04-09t12:00:00Z",  # lowercase T
        "2026-04-09T12:00:00z",  # lowercase Z
        "2026-13-09T12:00:00Z",  # invalid month
        "2026-04-32T12:00:00Z",  # invalid day
        "2026-04-09T25:00:00Z",  # invalid hour
        "",  # empty
        "garbage",
    ],
)
def test_malformed_timestamps_rejected(bad):
    ar = _valid_action_record()
    ar["timestamp"] = bad
    receipt = _sign_action_record(ar)
    result = pipelock_verify.verify(json.dumps(receipt))
    assert not result.valid, f"{bad!r} should have been rejected"


@pytest.mark.parametrize(
    "good",
    [
        "2026-04-09T12:00:00Z",
        "2026-04-09T12:00:00.123Z",
        "2026-04-09T12:00:00.123456789Z",
        "2026-04-09T12:00:00+00:00",
        "2026-04-09T12:00:00-07:00",
    ],
)
def test_valid_rfc3339_timestamps_accepted(good):
    ar = _valid_action_record()
    ar["timestamp"] = good
    receipt = _sign_action_record(ar)
    result = pipelock_verify.verify(json.dumps(receipt))
    assert result.valid, f"{good!r} should have been accepted: {result.error}"


# --- Finding 2: empty chain handling at CLI layer ---


def test_cli_rejects_empty_jsonl(tmp_path, capsys):
    """An empty .jsonl file must exit 1 with a 'No receipts found' message.

    Matches internal/cli/signing/receipt.go verifyChainFromFile which errors
    out when len(receipts) == 0.
    """
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")

    exit_code = main([str(empty)])
    out = capsys.readouterr().out
    assert exit_code == 1
    assert "No receipts found" in out


def test_cli_rejects_jsonl_with_only_non_receipt_entries(tmp_path, capsys):
    """A flight-recorder JSONL containing only checkpoints (no receipts)
    must also produce 'No receipts found', because _read_jsonl skips
    non-receipt entry types and the chain ends up empty."""
    f = tmp_path / "checkpoints-only.jsonl"
    # A plausible non-receipt flight-recorder entry.
    f.write_text(
        json.dumps(
            {
                "v": 1,
                "seq": 0,
                "ts": "2026-04-09T13:50:00Z",
                "type": "checkpoint",
                "transport": "",
                "summary": "checkpoint",
                "detail": {"entry_count": 0},
                "prev_hash": "genesis",
                "hash": "0" * 64,
            }
        )
        + "\n"
    )

    exit_code = main([str(f)])
    out = capsys.readouterr().out
    assert exit_code == 1
    assert "No receipts found" in out


def test_library_verify_chain_preserves_empty_is_valid(tmp_path):
    """The library function stays permissive (matches receipt.VerifyChain
    in Go). CLI wraps it with the "must have at least one" rule."""
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")

    result = pipelock_verify.verify_chain(empty)
    assert result.valid
    assert result.receipt_count == 0


# --- Finding 3: InvalidReceiptError must not escape ---


def test_cli_handles_unrecognized_jsonl_object(tmp_path, capsys):
    """A .jsonl file containing a valid JSON object that is neither a
    receipt nor a flight-recorder entry must fail cleanly, not crash.
    """
    f = tmp_path / "garbage.jsonl"
    f.write_text('{"foo":1}\n')

    exit_code = main([str(f)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "CHAIN BROKEN" in out
    assert "parsing JSONL" in out or "unrecognized" in out


def test_verify_chain_library_handles_unrecognized_object(tmp_path):
    """verify_chain() must return a ChainResult, not raise."""
    f = tmp_path / "garbage.jsonl"
    f.write_text('{"foo":1}\n')

    result = pipelock_verify.verify_chain(f)
    assert not result.valid
    assert result.error is not None
    assert "unrecognized" in result.error or "not a receipt" in result.error


def test_verify_chain_library_handles_mixed_garbage(tmp_path):
    """A valid receipt followed by a garbage object should fail on the
    second line, not crash."""
    good = (CONFORMANCE_DIR / "valid-single.json").read_text()
    good_compact = json.dumps(json.loads(good))  # squash to one line

    f = tmp_path / "mixed.jsonl"
    f.write_text(good_compact + "\n" + '{"foo":1}\n')

    result = pipelock_verify.verify_chain(f)
    assert not result.valid
    assert result.error is not None


# --- Finding 5: delegation_chain may be null (production emitter uses nil) ---


def test_delegation_chain_null_round_trips():
    """The production emitter writes ``DelegationChain: nil`` which Go
    serializes as ``"delegation_chain":null``. Python must accept that
    and re-canonicalize it the same way so signatures still verify."""
    ar = _valid_action_record()
    ar["delegation_chain"] = None
    receipt = _sign_action_record(ar)

    # Round-trip through JSON to make sure None survives as null. Use
    # compact separators so we match the substring regardless of whether
    # json.dumps inserts spaces.
    serialized = json.dumps(receipt, separators=(",", ":"))
    assert '"delegation_chain":null' in serialized

    result = pipelock_verify.verify(serialized)
    assert result.valid, f"nil delegation_chain should verify: {result.error}"


def test_delegation_chain_null_canonicalizes_as_null():
    """Canonical bytes must contain the literal token 'null' for a nil
    delegation_chain, matching Go's json.Marshal of a nil slice."""
    ar = _valid_action_record()
    ar["delegation_chain"] = None
    canonical = canonicalize_action_record(ar)
    assert b'"delegation_chain":null' in canonical
