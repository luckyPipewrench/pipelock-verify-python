"""Regressions for review findings on 2026-04-09.

Each test reproduces a concrete divergence from the Go reference that the
original implementation missed. The goal is a red test first, then the fix,
so these exact failure modes can never quietly come back.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import pipelock_verify
from pipelock_verify.__main__ import main
from pipelock_verify._canonical import canonicalize_action_record, canonicalize_receipt
from pipelock_verify._verify import _parse_receipt

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


# --- Finding 6: v2-in-chain fail-closed should report receipt's chain_seq ---


def test_v2_in_chain_fail_closed_uses_declared_chain_seq(tmp_path):
    """When verify_chain encounters an evidence_receipt_v2 in v0.2.0 it
    fails closed (v2 chain bridging is a v0.3 follow-up). The reported
    broken_at_seq must reflect the receipt's declared chain_seq, not the
    list index, so auditors see the same sequence the emitter wrote."""
    f = tmp_path / "chain.jsonl"
    receipt = {"record_type": "evidence_receipt_v2", "payload": {}, "chain_seq": 42}
    f.write_text(json.dumps(receipt) + "\n")

    result = pipelock_verify.verify_chain(f)
    assert not result.valid
    assert result.broken_at_seq == 42, f"want chain_seq=42 (declared), got {result.broken_at_seq}"


def test_v2_in_chain_fallback_to_index_when_chain_seq_missing(tmp_path):
    """When the v2 receipt omits chain_seq the fail-closed branch falls
    back to the list index so broken_at_seq is never None."""
    f = tmp_path / "chain.jsonl"
    receipt = {"record_type": "evidence_receipt_v2", "payload": {}}  # no chain_seq
    f.write_text(json.dumps(receipt) + "\n")

    result = pipelock_verify.verify_chain(f)
    assert not result.valid
    assert result.broken_at_seq == 0


def test_v2_in_chain_fallback_to_index_when_chain_seq_not_int(tmp_path):
    """A non-int chain_seq (string, bool, None) is rejected and the
    fail-closed branch falls back to the list index. The receipt is
    being rejected anyway; the fallback keeps broken_at_seq typed."""
    f = tmp_path / "chain.jsonl"
    receipt = {"record_type": "evidence_receipt_v2", "payload": {}, "chain_seq": "garbage"}
    f.write_text(json.dumps(receipt) + "\n")

    result = pipelock_verify.verify_chain(f)
    assert not result.valid
    assert result.broken_at_seq == 0


# --- Finding 7: v1 chain/session-control fail-closed parity ---


def _write_signed_chain(tmp_path: Path, *receipts: dict) -> Path:
    f = tmp_path / "chain.jsonl"
    f.write_text("\n".join(json.dumps(r, separators=(",", ":")) for r in receipts) + "\n")
    return f


def _receipt_hash(receipt: dict) -> str:
    return hashlib.sha256(canonicalize_receipt(receipt)).hexdigest()


def test_verify_chain_rejects_bool_chain_seq_even_with_valid_signature(tmp_path):
    ar = _valid_action_record()
    ar["action_id"] = "bool-chain-seq"
    ar["chain_seq"] = False
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, receipt))

    assert not result.valid
    assert "chain_seq must be a uint64" in (result.error or "")


def test_verify_chain_rejects_negative_chain_seq_even_with_valid_signature(tmp_path):
    ar = _valid_action_record()
    ar["action_id"] = "negative-chain-seq"
    ar["chain_seq"] = -1
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, receipt))

    assert not result.valid
    assert "chain_seq must be a uint64" in (result.error or "")


def test_verify_chain_rejects_truncated_legacy_root_segment(tmp_path):
    ar = _valid_action_record()
    ar["action_id"] = "truncated-root-segment"
    ar["chain_seq"] = 7
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, receipt))

    assert not result.valid
    assert result.broken_at_seq == 7
    assert "root receipt segment must start at chain_seq 0" in (result.error or "")


@pytest.mark.parametrize(
    ("session_control", "want"),
    [
        ("not-object", "session_control must be an object"),
        ({"kind": "session_open"}, "session_control must carry exactly one payload"),
        (
            {"kind": "session_open", "heartbeat": {}},
            "session_open kind missing open payload",
        ),
        (
            {"kind": "heartbeat", "open": {}},
            "heartbeat kind missing heartbeat payload",
        ),
        (
            {"kind": "session_close", "open": {}},
            "session_close kind missing close payload",
        ),
        ({"kind": "unknown", "open": {}}, "unknown session_control kind"),
        (
            {"kind": "heartbeat", "heartbeat": {"beat": True}},
            "session_heartbeat beat must be a uint64",
        ),
        (
            {"kind": "session_open", "open": {"heartbeat_seconds": True}},
            "session_open heartbeat_seconds must be an integer",
        ),
        (
            {"kind": "session_open", "open": {"heartbeat_seconds": 2**63}},
            "session_open heartbeat_seconds must be an integer",
        ),
    ],
)
def test_verify_chain_rejects_malformed_session_control_even_with_valid_signature(
    tmp_path,
    session_control,
    want,
):
    ar = _valid_action_record()
    ar["action_id"] = "malformed-session-control"
    ar["session_control"] = session_control
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, receipt))

    assert not result.valid
    assert want in (result.error or "")


def test_verify_chain_rejects_first_run_nonce_without_session_open(tmp_path):
    ar = _valid_action_record()
    ar["action_id"] = "run-nonce-no-open"
    ar["run_nonce"] = "run-attack"
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, receipt))

    assert not result.valid
    assert "run_nonce first receipt is not a matching session_open" in (result.error or "")


def test_verify_chain_rejects_unknown_signed_v1_field_even_with_valid_signature(tmp_path):
    ar = _valid_action_record()
    ar["action_id"] = "unknown-field"
    ar["unsigned_but_plausible"] = "display-me"
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, receipt))

    assert not result.valid
    assert "unknown signed field" in (result.error or "")


@pytest.mark.parametrize(
    ("field", "value", "want"),
    [
        ("redaction", {"unknown": 1}, "redaction carries unknown signed field"),
        ("redaction", {"total_redactions": True}, "redaction total_redactions must be an integer"),
        ("shield", {"unknown": 1}, "shield carries unknown signed field"),
        ("shield", {"total_rewrites": True}, "shield total_rewrites must be an integer"),
        (
            "recent_taint_sources",
            [{"url": "https://src.example", "kind": "k", "level": True}],
            "recent_taint_sources[0] level must be a uint8",
        ),
        (
            "recent_taint_sources",
            [{"url": "https://src.example", "kind": "k", "level": 4, "unknown": "x"}],
            "recent_taint_sources[0] carries unknown signed field",
        ),
    ],
)
def test_verify_chain_rejects_malformed_existing_signed_nested_objects(
    tmp_path,
    field,
    value,
    want,
):
    ar = _valid_action_record()
    ar["action_id"] = "malformed-existing-nested"
    ar[field] = value
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, receipt))

    assert not result.valid
    assert want in (result.error or "")


def test_verify_chain_rejects_first_receipt_key_transition_even_with_valid_signature(tmp_path):
    ar = _valid_action_record()
    ar["action_id"] = "first-key-transition"
    ar["key_transition"] = {
        "prior_signer_key": "old-key",
        "prior_chain_seq": 99,
        "prior_chain_hash": "old-hash",
    }
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, receipt))

    assert not result.valid
    assert "chain starts at a key_transition segment" in (result.error or "")


def test_verify_chain_rejects_non_genesis_key_transition_even_with_valid_signature(tmp_path):
    first = _sign_action_record(_valid_action_record())
    ar = _valid_action_record()
    ar["action_id"] = "non-genesis-key-transition"
    ar["timestamp"] = "2026-04-09T13:50:01Z"
    ar["chain_seq"] = 1
    ar["chain_prev_hash"] = _receipt_hash(first)
    ar["key_transition"] = {
        "prior_signer_key": first["signer_key"],
        "prior_chain_seq": 0,
        "prior_chain_hash": ar["chain_prev_hash"],
    }
    second = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, first, second))

    assert not result.valid
    assert "key_transition marker on a non-genesis receipt" in (result.error or "")


def test_verify_chain_rejects_session_control_without_receipt_run_nonce(tmp_path):
    ar = _valid_action_record()
    ar["action_id"] = "session-control-no-receipt-run"
    ar["session_control"] = {
        "kind": "heartbeat",
        "heartbeat": {
            "run_nonce": "run-2",
            "open_nonce": "open-2",
            "beat": 1,
            "chain_head": "genesis",
            "chain_seq_head": 0,
            "heartbeat_time": "2026-04-09T13:50:01Z",
            "fsync_errors_gated": 0,
            "durability_blocks": 0,
        },
    }
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, receipt))

    assert not result.valid
    assert "session_control receipt missing run_nonce" in (result.error or "")


def test_verify_chain_accepts_restart_session_open_bound_to_prior_tail(tmp_path):
    first = _sign_action_record(_valid_action_record())
    prior_hash = _receipt_hash(first)
    ar = _valid_action_record()
    ar["action_id"] = "good-restart-open"
    ar["timestamp"] = "2026-04-09T13:50:01Z"
    ar["chain_seq"] = 1
    ar["chain_prev_hash"] = prior_hash
    ar["run_nonce"] = "run-2"
    ar["session_control"] = {
        "kind": "session_open",
        "open": {
            "run_nonce": "run-2",
            "open_nonce": "open-2",
            "recorder_session": "proxy",
            "policy_hash": "policy",
            "signer_key_epoch": first["signer_key"],
            "heartbeat_seconds": 60,
            "chain_open_seq": 1,
            "prior_chain_head": prior_hash,
            "prior_chain_seq": 0,
        },
    }
    second = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, first, second))

    assert result.valid, result.error


@pytest.mark.parametrize(
    ("mutate", "want"),
    [
        (
            lambda open_payload, prior_hash: open_payload.update(
                {"prior_chain_head": "not-the-prior-tail"}
            ),
            "session_open prior_chain_head does not match prior tail hash",
        ),
        (
            lambda open_payload, prior_hash: open_payload.update({"prior_chain_seq": 99}),
            "session_open prior_chain_seq does not match prior tail seq",
        ),
        (
            lambda open_payload, prior_hash: open_payload.update({"chain_open_seq": 2}),
            "session_open chain_open_seq does not match receipt chain_seq",
        ),
        (
            lambda open_payload, prior_hash: open_payload.update({"genesis_hash": "g1:bad"}),
            "restart session_open must not carry genesis_hash",
        ),
    ],
)
def test_verify_chain_rejects_malformed_restart_session_open_even_with_valid_signature(
    tmp_path,
    mutate,
    want,
):
    first = _sign_action_record(_valid_action_record())
    prior_hash = _receipt_hash(first)
    ar = _valid_action_record()
    ar["action_id"] = "bad-restart-open"
    ar["timestamp"] = "2026-04-09T13:50:01Z"
    ar["chain_seq"] = 1
    ar["chain_prev_hash"] = prior_hash
    ar["run_nonce"] = "run-2"
    open_payload = {
        "run_nonce": "run-2",
        "open_nonce": "open-2",
        "recorder_session": "proxy",
        "policy_hash": "policy",
        "signer_key_epoch": first["signer_key"],
        "heartbeat_seconds": 60,
        "chain_open_seq": 1,
        "prior_chain_head": prior_hash,
        "prior_chain_seq": 0,
    }
    mutate(open_payload, prior_hash)
    ar["session_control"] = {"kind": "session_open", "open": open_payload}
    second = _sign_action_record(ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, first, second))

    assert not result.valid
    assert want in (result.error or "")


def test_verify_chain_rejects_heartbeat_with_wrong_tail_binding(tmp_path):
    first = _sign_action_record(_valid_action_record())
    prior_hash = _receipt_hash(first)
    open_ar = _valid_action_record()
    open_ar["action_id"] = "restart-open-before-heartbeat"
    open_ar["timestamp"] = "2026-04-09T13:50:01Z"
    open_ar["chain_seq"] = 1
    open_ar["chain_prev_hash"] = prior_hash
    open_ar["run_nonce"] = "run-2"
    open_ar["session_control"] = {
        "kind": "session_open",
        "open": {
            "run_nonce": "run-2",
            "open_nonce": "open-2",
            "recorder_session": "proxy",
            "policy_hash": "policy",
            "signer_key_epoch": first["signer_key"],
            "heartbeat_seconds": 60,
            "chain_open_seq": 1,
            "prior_chain_head": prior_hash,
            "prior_chain_seq": 0,
        },
    }
    second = _sign_action_record(open_ar)
    second_hash = _receipt_hash(second)

    heartbeat_ar = _valid_action_record()
    heartbeat_ar["action_id"] = "bad-heartbeat"
    heartbeat_ar["timestamp"] = "2026-04-09T13:50:02Z"
    heartbeat_ar["chain_seq"] = 2
    heartbeat_ar["chain_prev_hash"] = second_hash
    heartbeat_ar["run_nonce"] = "run-2"
    heartbeat_ar["session_control"] = {
        "kind": "heartbeat",
        "heartbeat": {
            "run_nonce": "run-2",
            "open_nonce": "open-2",
            "beat": 1,
            "chain_head": "not-the-prior-tail",
            "chain_seq_head": 1,
            "heartbeat_time": "2026-04-09T13:50:02Z",
            "fsync_errors_gated": 0,
            "durability_blocks": 0,
        },
    }
    third = _sign_action_record(heartbeat_ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, first, second, third))

    assert not result.valid
    assert "heartbeat chain_head mismatch" in (result.error or "")


def test_verify_chain_rejects_session_close_with_wrong_root_hash(tmp_path):
    first = _sign_action_record(_valid_action_record())
    prior_hash = _receipt_hash(first)
    open_ar = _valid_action_record()
    open_ar["action_id"] = "restart-open-before-close"
    open_ar["timestamp"] = "2026-04-09T13:50:01Z"
    open_ar["chain_seq"] = 1
    open_ar["chain_prev_hash"] = prior_hash
    open_ar["run_nonce"] = "run-2"
    open_ar["session_control"] = {
        "kind": "session_open",
        "open": {
            "run_nonce": "run-2",
            "open_nonce": "open-2",
            "recorder_session": "proxy",
            "policy_hash": "policy",
            "signer_key_epoch": first["signer_key"],
            "heartbeat_seconds": 60,
            "chain_open_seq": 1,
            "prior_chain_head": prior_hash,
            "prior_chain_seq": 0,
        },
    }
    second = _sign_action_record(open_ar)
    second_hash = _receipt_hash(second)

    close_ar = _valid_action_record()
    close_ar["action_id"] = "bad-close"
    close_ar["timestamp"] = "2026-04-09T13:50:02Z"
    close_ar["chain_seq"] = 2
    close_ar["chain_prev_hash"] = second_hash
    close_ar["run_nonce"] = "run-2"
    close_ar["session_control"] = {
        "kind": "session_close",
        "close": {
            "run_nonce": "run-2",
            "open_nonce": "open-2",
            "final_seq": 2,
            "root_hash": "not-the-prior-tail",
            "receipt_count": 3,
            "close_reason": "normal",
            "fsync_errors_gated": 0,
            "durability_blocks": 0,
        },
    }
    third = _sign_action_record(close_ar)

    result = pipelock_verify.verify_chain(_write_signed_chain(tmp_path, first, second, third))

    assert not result.valid
    assert "session_close root_hash mismatch" in (result.error or "")


# The key_transition SHAPE gate is only reachable through the single-receipt
# path: verify_chain() rejects any key_transition marker by POSITION first
# (seq 0 -> "starts at a key_transition segment", seq > 0 -> "non-genesis"),
# so a chain-level test can never exercise shape validation. Without these,
# _validate_key_transition_shape passes every test even when deleted.
@pytest.mark.parametrize(
    ("marker", "want"),
    [
        (
            {"prior_signer_key": "old", "prior_chain_seq": 0, "prior_chain_hash": "h", "bogus": 1},
            "key_transition carries unknown signed field",
        ),
        ({"prior_signer_key": 123}, "key_transition prior_signer_key must be a string"),
        ({"prior_chain_hash": 123}, "key_transition prior_chain_hash must be a string"),
        ({"prior_chain_seq": -1}, "key_transition prior_chain_seq must be a uint64"),
        ({"prior_chain_seq": 1.0}, "key_transition prior_chain_seq must be a uint64"),
        ({"prior_chain_seq": True}, "key_transition prior_chain_seq must be a uint64"),
        ("not-an-object", "key_transition must be an object"),
    ],
)
def test_verify_rejects_malformed_key_transition_even_with_valid_signature(marker, want):
    ar = _valid_action_record()
    ar["action_id"] = "malformed-key-transition"
    ar["key_transition"] = marker
    receipt = _sign_action_record(ar)

    result = pipelock_verify.verify(json.dumps(receipt))

    assert not result.valid
    assert want in (result.error or "")


def test_receipt_chain_hash_covers_the_unsigned_ext_bag():
    """`ext` is unsigned but IS part of Go's chain hash.

    Go's ReceiptHash is sha256 over json.Marshal(Receipt), and Receipt.Ext is a
    marshalled field. A verifier that drops ext from the receipt envelope agrees
    with Go only while ext is absent, and lets ext be attached or altered on a
    receipt without changing the chain hash it commits to. ext stays out of the
    SIGNED action-record projection; this is the envelope hash only.
    """
    base = {
        "version": 1,
        "action_record": {"version": 1},
        "signature": "ed25519:aa",
        "signer_key": "bb",
    }
    with_ext = dict(base) | {"ext": {"note": "advisory"}}
    altered_ext = dict(base) | {"ext": {"note": "tampered"}}

    bare = canonicalize_receipt(base)
    tagged = canonicalize_receipt(with_ext)
    altered = canonicalize_receipt(altered_ext)

    assert b'"ext"' in tagged
    assert bare != tagged, "ext must change the receipt envelope hash"
    assert tagged != altered, "altering ext must change the receipt envelope hash"
    # ext is ordered last, matching the Go struct.
    assert tagged.decode().index('"ext"') > tagged.decode().index('"signer_key"')


@pytest.mark.parametrize(
    ("raw_ext", "want_ext"),
    [
        ('{"b":2,"a":1}', '{"b":2,"a":1}'),
        ('{"s":"<&\u2028\u2029"}', '{"s":"\\u003c\\u0026\\u2028\\u2029"}'),
        ('[ 1, {"z":0, "y":1} ]', '[1,{"z":0,"y":1}]'),
        (
            '{"n":1e+06,"big":123456789012345678901234567890}',
            '{"n":1e+06,"big":123456789012345678901234567890}',
        ),
        ("null", "null"),
        ("{}", "{}"),
        ("[]", "[]"),
        ("false", "false"),
        ("0", "0"),
        ('""', '""'),
    ],
)
def test_receipt_ext_matches_go_rawmessage_compaction(raw_ext: str, want_ext: str) -> None:
    """ext is RawMessage-like: present JSON zeros stay, inner order is not sorted."""

    receipt = _sign_action_record(_valid_action_record())
    raw = json.dumps(receipt, separators=(",", ":"))
    raw = raw[:-1] + f',"ext":{raw_ext}' + "}"
    parsed = _parse_receipt(raw)

    canonical = canonicalize_receipt(parsed).decode()

    assert canonical.endswith(f',"ext":{want_ext}}}')


def test_receipt_ext_from_plain_dict_preserves_insertion_order_and_json_zero_values() -> None:
    receipt = _sign_action_record(_valid_action_record())
    receipt["ext"] = {"b": 2, "a": 1}

    canonical = canonicalize_receipt(receipt).decode()

    assert canonical.endswith(',"ext":{"b":2,"a":1}}')

    ext_values: tuple[Any, ...] = (None, {}, [], False, 0, "")
    for ext in ext_values:
        receipt["ext"] = ext
        assert ',"ext":' in canonicalize_receipt(receipt).decode()


@pytest.mark.parametrize("detail_as_string", [False, True])
def test_verify_chain_preserves_raw_ext_from_recorder_detail_shapes(
    tmp_path: Path, detail_as_string: bool
) -> None:
    receipt = _sign_action_record(_valid_action_record())
    raw_receipt = json.dumps(receipt, separators=(",", ":"))
    raw_receipt = (
        raw_receipt[:-1] + ',"ext":{"n":1e+06,"nested":{"b":2,"a":1},"zero":0,"empty":{}}' + "}"
    )
    expected_root = hashlib.sha256(canonicalize_receipt(_parse_receipt(raw_receipt))).hexdigest()

    if detail_as_string:
        detail = json.dumps(raw_receipt, separators=(",", ":"))
    else:
        detail = raw_receipt
    path = tmp_path / "chain.jsonl"
    path.write_text(f'{{"type":"action_receipt","detail":{detail}}}\n')

    result = pipelock_verify.verify_chain(path)

    assert result.valid, result.error
    assert result.root_hash == expected_root


def test_ext_stays_out_of_the_signed_action_record_projection():
    """ext is advisory and unsigned: it must never enter the signing input."""
    ar = _valid_action_record()
    ar["ext"] = {"note": "advisory"}

    # ext is not an action_record field at all, so the shape gate rejects it.
    receipt = _sign_action_record(ar)
    result = pipelock_verify.verify(json.dumps(receipt))

    assert not result.valid
    assert "unknown signed field" in (result.error or "")


def test_dunder_version_matches_pyproject():
    """`__version__` and the packaging version must not drift apart.

    The release workflow checks the git tag against pyproject.toml, and nothing
    checked pyproject.toml against `__version__`, so the package could ship
    announcing a version it was not. This closes that side of the triangle.
    """
    # Parsed with a regex rather than tomllib, which is 3.11+ while this
    # package still supports 3.10.
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    match = re.search(r'^version = "([^"]+)"', pyproject.read_text(encoding="utf-8"), re.MULTILINE)
    assert match is not None, "could not find the version in pyproject.toml"
    declared = match.group(1)

    assert pipelock_verify.__version__ == declared, (
        f"__version__ is {pipelock_verify.__version__} but pyproject.toml says {declared}"
    )
