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

from pipelock_verify._canonical import (
    _ACTION_RECORD_FIELDS,
    _KEY_TRANSITION_FIELDS,
    _SESSION_CLOSE_FIELDS,
    _SESSION_CONTROL_FIELDS,
    _SESSION_HEARTBEAT_FIELDS,
    _SESSION_OPEN_FIELDS,
    canonicalize_action_record,
)
from pipelock_verify._common import (
    DuplicateKeyError,
    InvalidReceiptError,
    loads_no_duplicate_keys,
)
from pipelock_verify._verify import _compute_session_open_genesis, verify

# Fast offline mirror guard. The authoritative live drift gate is
# scripts/check_go_canonical_contract.py, which fetches Go's
# internal/receipt/canonical.go at a resolved commit and fails closed.
CANONICAL_GO_MESSAGE = (
    "Checked-in Python mirror of Go internal/receipt/canonical.go "
    "actionRecordCanonicalV1 drifted; refresh this list from Go origin/main."
)

EXPECTED_ACTION_RECORD_CANONICAL_V1: list[tuple[str, bool, str | None]] = [
    ("version", False, None),
    ("action_id", False, None),
    ("parent_action_id", True, None),
    ("action_type", False, None),
    ("timestamp", False, None),
    ("principal", False, None),
    ("actor", False, None),
    ("delegation_chain", False, None),
    ("target", False, None),
    ("intent", True, None),
    ("data_classes_in", True, None),
    ("data_classes_out", True, None),
    ("side_effect_class", False, None),
    ("reversibility", False, None),
    ("policy_hash", False, None),
    ("verdict", False, None),
    ("decision_phase", True, None),
    ("defer_id", True, None),
    ("resolution_policy", True, None),
    ("resolution_source", True, None),
    ("session_id", True, None),
    ("session_id_original", True, None),
    ("session_taint_level", True, None),
    ("session_contaminated", True, None),
    ("recent_taint_sources", True, "taint_source"),
    ("session_task_id", True, None),
    ("session_task_label", True, None),
    ("authority_kind", True, None),
    ("taint_decision", True, None),
    ("taint_decision_reason", True, None),
    ("task_override_applied", True, None),
    ("contract_winning_source", True, None),
    ("contract_live_verdict", True, None),
    ("contract_policy_sources", True, None),
    ("contract_rule_id", True, None),
    ("active_manifest_hash", True, None),
    ("contract_hash", True, None),
    ("contract_selector_id", True, None),
    ("contract_generation", True, None),
    ("transport", False, None),
    ("method", True, None),
    ("layer", True, None),
    ("pattern", True, None),
    ("severity", True, None),
    ("redaction", True, "redaction"),
    ("shield", True, "shield"),
    ("request_id", True, None),
    ("chain_prev_hash", False, None),
    ("chain_seq", False, None),
    ("run_nonce", True, None),
    ("key_transition", True, "key_transition"),
    ("session_control", True, "session_control"),
    ("venue", True, None),
    ("jurisdiction", True, None),
    ("rulebook_id", True, None),
    ("remedy_class", True, None),
    ("contestation_window", True, None),
    ("precedent_refs", True, None),
]

EXPECTED_KEY_TRANSITION_CANONICAL_V1: list[tuple[str, bool, str | None]] = [
    ("prior_signer_key", False, None),
    ("prior_chain_seq", False, None),
    ("prior_chain_hash", False, None),
]

EXPECTED_SESSION_CONTROL_CANONICAL_V1: list[tuple[str, bool, str | None]] = [
    ("kind", False, None),
    ("open", True, "session_open"),
    ("heartbeat", True, "session_heartbeat"),
    ("close", True, "session_close"),
]

EXPECTED_SESSION_OPEN_CANONICAL_V1: list[tuple[str, bool, str | None]] = [
    ("run_nonce", False, None),
    ("open_nonce", False, None),
    ("recorder_session", False, None),
    ("policy_hash", False, None),
    ("signer_key_epoch", False, None),
    ("heartbeat_seconds", False, None),
    ("chain_open_seq", False, None),
    ("prior_chain_head", True, None),
    ("prior_chain_seq", True, None),
    ("genesis_hash", True, None),
    ("genesis_anchor_head", True, None),
    ("genesis_anchor_log", True, None),
    ("posture_capsule_sha256", True, None),
    ("posture_signer_key_id", True, None),
    ("containment_nonce", True, None),
    ("contained_uid", True, None),
]

EXPECTED_SESSION_HEARTBEAT_CANONICAL_V1: list[tuple[str, bool, str | None]] = [
    ("run_nonce", False, None),
    ("open_nonce", False, None),
    ("beat", False, None),
    ("chain_head", False, None),
    ("chain_seq_head", False, None),
    ("heartbeat_time", False, None),
    ("fsync_errors_gated", False, None),
    ("durability_blocks", False, None),
]

EXPECTED_SESSION_CLOSE_CANONICAL_V1: list[tuple[str, bool, str | None]] = [
    ("run_nonce", False, None),
    ("open_nonce", False, None),
    ("final_seq", False, None),
    ("root_hash", False, None),
    ("receipt_count", False, None),
    ("close_reason", False, None),
    ("fsync_errors_gated", False, None),
    ("durability_blocks", False, None),
]


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
        "decision_phase": "intent",
        "defer_id": "defer-1",
        "resolution_policy": "operator",
        "resolution_source": "scanner",
        "session_id": "session-1",
        "session_id_original": "session-original-1",
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
        "run_nonce": "run-1",
        "key_transition": {
            "prior_signer_key": "key-a",
            "prior_chain_seq": 6,
            "prior_chain_hash": "hash-a",
        },
        "session_control": {
            "kind": "heartbeat",
            "heartbeat": {
                "run_nonce": "run-1",
                "open_nonce": "open-1",
                "beat": 1,
                "chain_head": "head-1",
                "chain_seq_head": 0,
                "heartbeat_time": "2026-04-15T12:00:01Z",
                "fsync_errors_gated": 0,
                "durability_blocks": 1,
            },
        },
    }


def test_action_record_field_list_matches_canonical_go_projection():
    assert _ACTION_RECORD_FIELDS == EXPECTED_ACTION_RECORD_CANONICAL_V1, CANONICAL_GO_MESSAGE


def test_nested_session_field_lists_match_canonical_go_projection():
    assert _KEY_TRANSITION_FIELDS == EXPECTED_KEY_TRANSITION_CANONICAL_V1, CANONICAL_GO_MESSAGE
    assert _SESSION_CONTROL_FIELDS == EXPECTED_SESSION_CONTROL_CANONICAL_V1, CANONICAL_GO_MESSAGE
    assert _SESSION_OPEN_FIELDS == EXPECTED_SESSION_OPEN_CANONICAL_V1, CANONICAL_GO_MESSAGE
    assert _SESSION_HEARTBEAT_FIELDS == EXPECTED_SESSION_HEARTBEAT_CANONICAL_V1, (
        CANONICAL_GO_MESSAGE
    )
    assert _SESSION_CLOSE_FIELDS == EXPECTED_SESSION_CLOSE_CANONICAL_V1, CANONICAL_GO_MESSAGE


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
        "key_transition",
        "session_control",
    ):
        assert f'"{field}"' in canonical, f"{field} missing from canonical output"


def test_v1_decision_fields_ordered_after_verdict_before_taint_block():
    canonical = canonicalize_action_record(_full_field_record()).decode()
    assert (
        canonical.index('"verdict"')
        < canonical.index('"decision_phase"')
        < canonical.index('"defer_id"')
        < canonical.index('"resolution_policy"')
        < canonical.index('"resolution_source"')
        < canonical.index('"session_id"')
        < canonical.index('"session_id_original"')
        < canonical.index('"session_taint_level"')
    )


def test_session_control_payload_keys_in_go_struct_order():
    canonical = canonicalize_action_record(_full_field_record()).decode()
    assert canonical.index('"run_nonce"') < canonical.index('"key_transition"')
    assert canonical.index('"key_transition"') < canonical.index('"session_control"')
    session_control = canonical[canonical.index('"session_control":') :]
    assert (
        session_control.index('"kind"')
        < session_control.index('"heartbeat"')
        < session_control.index('"beat"')
        < session_control.index('"chain_head"')
        < session_control.index('"fsync_errors_gated"')
        < session_control.index('"durability_blocks"')
    )


def test_session_open_genesis_matches_go_golden_with_non_empty_tail_fields():
    # Mirrors internal/receipt/session_control_test.go fixedSessionOpen() and
    # goldenSessionOpenGenesis. The non-empty tail fields catch wrong spelling
    # or order for the posture/containment binding.
    open_payload = {
        "run_nonce": "run-nonce-aaaa",
        "open_nonce": "open-nonce-bbbb",
        "recorder_session": "rec-sess-cccc",
        "policy_hash": "policy-hash-dddd",
        "signer_key_epoch": "epoch-3",
        "heartbeat_seconds": 60,
        "chain_open_seq": 0,
        "genesis_anchor_head": "anchor-head-eeee",
        "genesis_anchor_log": "anchor-log-ffff",
        "posture_capsule_sha256": "capsule-sha-0000",
        "containment_nonce": "contain-nonce-1111",
        "contained_uid": "966",
    }
    assert (
        _compute_session_open_genesis(open_payload)
        == "g1:4e3d35d36683d6d5c65e427b447ada0d2e9098befff7caad954972bdadd405ec"
    )


def test_present_empty_key_transition_emits_go_zero_fields():
    record = _full_field_record()
    record["key_transition"] = {}
    canonical = canonicalize_action_record(record).decode()
    assert (
        '"key_transition":{"prior_signer_key":"","prior_chain_seq":0,"prior_chain_hash":""}'
    ) in canonical


def test_present_empty_session_control_emits_go_zero_kind():
    record = _full_field_record()
    record["session_control"] = {}
    canonical = canonicalize_action_record(record).decode()
    assert '"session_control":{"kind":""}' in canonical


def test_session_control_open_payload_keys_in_go_struct_order_with_zero_uints():
    record = _full_field_record()
    record["session_control"] = {
        "kind": "session_open",
        "open": {
            "run_nonce": "run-1",
            "open_nonce": "open-1",
            "recorder_session": "proxy",
            "policy_hash": "policy-1",
            "signer_key_epoch": "epoch-1",
            "heartbeat_seconds": 0,
            "chain_open_seq": 0,
            "genesis_hash": "g1:abc",
            "genesis_anchor_head": "anchor-head",
            "genesis_anchor_log": "anchor-log",
            "posture_capsule_sha256": "capsule",
            "posture_signer_key_id": "posture-key",
            "containment_nonce": "containment",
            "contained_uid": "966",
        },
    }
    canonical = canonicalize_action_record(record).decode()
    assert (
        '"open":{"run_nonce":"run-1","open_nonce":"open-1",'
        '"recorder_session":"proxy","policy_hash":"policy-1",'
        '"signer_key_epoch":"epoch-1","heartbeat_seconds":0,'
        '"chain_open_seq":0,"genesis_hash":"g1:abc",'
        '"genesis_anchor_head":"anchor-head","genesis_anchor_log":"anchor-log",'
        '"posture_capsule_sha256":"capsule","posture_signer_key_id":"posture-key",'
        '"containment_nonce":"containment","contained_uid":"966"}'
    ) in canonical


def test_session_control_close_payload_keys_in_go_struct_order_with_zero_uints():
    record = _full_field_record()
    record["session_control"] = {
        "kind": "session_close",
        "close": {
            "run_nonce": "run-1",
            "open_nonce": "open-1",
            "final_seq": 10,
            "root_hash": "root-1",
            "receipt_count": 11,
            "close_reason": "graceful_shutdown",
            "fsync_errors_gated": 0,
            "durability_blocks": 0,
        },
    }
    canonical = canonicalize_action_record(record).decode()
    assert (
        '"close":{"run_nonce":"run-1","open_nonce":"open-1","final_seq":10,'
        '"root_hash":"root-1","receipt_count":11,"close_reason":"graceful_shutdown",'
        '"fsync_errors_gated":0,"durability_blocks":0}'
    ) in canonical


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
