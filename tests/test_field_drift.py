"""Regression tests for cross-language canonicalization drift and duplicate-key
rejection.

These cover the two fixes that closed real cross-language verification
differentials:

1. The v1 canonical field list was missing parent_action_id, the taint block,
   the contract block, severity, redaction, and shield — so any receipt carrying
   those fields recomputed a different signing hash and failed verification here
   while passing in Go. The field list now mirrors the full Go ActionRecord.
2. ``json.loads`` silently keeps the last value for a duplicate object key, so a
   receipt with a smuggled duplicate verdict could verify. The verify path now
   rejects duplicate keys at any nesting depth.

The tests are self-contained (no fixture files); the shared agent-egress-bench
corpus is exercised against this verifier by the cross-language gate in the
pipelock repository.
"""

from __future__ import annotations

import pytest

from pipelock_verify._canonical import canonicalize_action_record
from pipelock_verify._common import (
    DuplicateKeyError,
    InvalidReceiptError,
    loads_no_duplicate_keys,
)
from pipelock_verify._verify import verify


def _full_field_record() -> dict:
    """An action record populating one field from every block that was missing
    from the canonical list before the drift fix."""
    return {
        "version": 1,
        "action_id": "drift-0001",
        "parent_action_id": "drift-parent-0001",
        "action_type": "write",
        "timestamp": "2026-04-15T12:00:00Z",
        "principal": "org:test",
        "actor": "agent:test",
        "delegation_chain": ["grant"],
        "target": "https://example.com/spawn",
        "side_effect_class": "external_write",
        "reversibility": "compensatable",
        "policy_hash": "sha256:abc",
        "verdict": "allow",
        "session_taint_level": "suspected",
        "session_contaminated": True,
        "recent_taint_sources": [
            {
                "url": "https://src.example/a",
                "kind": "response_injection",
                "level": 4,
                "timestamp": "2026-04-15T12:00:00Z",
                "match_reason": "ignore_previous_instructions",
            }
        ],
        "session_task_id": "task-1",
        "authority_kind": "delegated",
        "contract_winning_source": "operator_policy",
        "contract_hash": "sha256:def",
        "contract_generation": 4,
        "transport": "https",
        "severity": "medium",
        "redaction": {
            "profile": "strict",
            "provider": "provider.example",
            "total_redactions": 1,
            "by_class": {"api_key": 1},
        },
        "shield": {
            "pipeline": "browser_shield_v1",
            "total_rewrites": 1,
            "agent_traps": 1,
        },
        "request_id": "req-1",
        "chain_prev_hash": "genesis",
        "chain_seq": 0,
        "run_nonce": "0123456789abcdef0123456789abcdef",
    }


def test_parent_action_id_ordered_after_action_id():
    canonical = canonicalize_action_record(_full_field_record()).decode()
    assert (
        '"action_id":"drift-0001","parent_action_id":"drift-parent-0001","action_type"' in canonical
    )


def test_shield_ordered_after_redaction_before_request_id():
    canonical = canonicalize_action_record(_full_field_record()).decode()
    # redaction object, then shield object, then request_id.
    assert '"shield":{' in canonical
    assert (
        canonical.index('"redaction":')
        < canonical.index('"shield":')
        < canonical.index('"request_id"')
    )


def test_nested_shield_keys_in_go_struct_order():
    canonical = canonicalize_action_record(_full_field_record()).decode()
    # pipeline, then total_rewrites, then agent_traps (declaration order).
    shield = canonical[canonical.index('"shield":') :]
    assert (
        shield.index('"pipeline"')
        < shield.index('"total_rewrites"')
        < shield.index('"agent_traps"')
    )


def test_taint_block_present_in_canonical():
    canonical = canonicalize_action_record(_full_field_record()).decode()
    for field in (
        "session_taint_level",
        "session_contaminated",
        "recent_taint_sources",
        "authority_kind",
        "contract_hash",
        "contract_generation",
        "severity",
        "run_nonce",
    ):
        assert f'"{field}"' in canonical, f"{field} missing from canonical output"


def test_nested_taint_source_level_is_numeric():
    canonical = canonicalize_action_record(_full_field_record()).decode()
    # session.TaintLevel is a uint8 -> serializes as a number, not a string.
    assert '"level":4' in canonical


def test_redaction_by_class_map_keys_sorted_like_go():
    # Go's json.Marshal sorts map keys; a verifier that preserves input order
    # diverges whenever by_class keys are not already sorted.
    record = _full_field_record()
    record["redaction"]["by_class"] = {"email": 2, "api_key": 1}
    canonical = canonicalize_action_record(record).decode()
    assert '"by_class":{"api_key":1,"email":2}' in canonical


# ---- duplicate-key rejection ----


def test_loads_rejects_top_level_duplicate():
    with pytest.raises(DuplicateKeyError):
        loads_no_duplicate_keys('{"a":1,"a":2}')


def test_loads_rejects_nested_duplicate():
    with pytest.raises(DuplicateKeyError):
        loads_no_duplicate_keys('{"x":{"a":1,"a":2}}')


def test_loads_rejects_duplicate_in_array_element():
    with pytest.raises(DuplicateKeyError):
        loads_no_duplicate_keys('{"arr":[{"a":1},{"a":1,"a":2}]}')


def test_loads_rejects_unicode_escaped_duplicate():
    # "a" decodes to "a"; must be caught (cross-language smuggling vector).
    with pytest.raises(DuplicateKeyError):
        loads_no_duplicate_keys('{"a":1,"\\u0061":2}')


def test_loads_rejects_over_deep_nesting():
    deep = "[" * 129 + "1" + "]" * 129
    with pytest.raises(InvalidReceiptError):
        loads_no_duplicate_keys(deep)


def test_loads_accepts_exact_max_nesting():
    max_depth = "[" * 128 + "1" + "]" * 128
    assert loads_no_duplicate_keys(max_depth) is not None


def test_loads_accepts_clean_nested_json():
    assert loads_no_duplicate_keys('{"a":1,"b":{"c":2},"d":[{"e":3},{"e":4}]}') == {
        "a": 1,
        "b": {"c": 2},
        "d": [{"e": 3}, {"e": 4}],
    }


def test_verify_rejects_duplicate_verdict_key():
    # A duplicate verdict key must be rejected at parse, before signature checks.
    receipt = (
        '{"version":1,"action_record":{"version":1,"action_id":"x",'
        '"action_type":"write","timestamp":"2026-04-15T12:00:00Z",'
        '"verdict":"allow","verdict":"block","target":"https://e.example",'
        '"transport":"https","chain_prev_hash":"genesis","chain_seq":0},'
        '"signature":"ed25519:00","signer_key":"00"}'
    )
    result = verify(receipt)
    assert not result.valid
    assert "duplicate object key" in (result.error or "")


def test_verify_rejects_duplicate_key_inside_string_detail():
    # Flight-recorder entries may carry detail as a JSON string. That inner JSON
    # must use the same duplicate-key rejecting loader as top-level receipts.
    entry = (
        '{"type":"action_receipt","detail":"{\\"version\\":1,'
        '\\"action_record\\":{\\"version\\":1,\\"verdict\\":\\"allow\\",'
        '\\"verdict\\":\\"block\\"},\\"signature\\":\\"ed25519:00\\",'
        '\\"signer_key\\":\\"00\\"}"}'
    )
    result = verify(entry)
    assert not result.valid
    assert "duplicate object key" in (result.error or "")
