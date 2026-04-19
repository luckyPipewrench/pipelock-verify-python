"""Unit tests for Go-compatible JSON canonicalization.

These tests do not touch the fixture files — they check that the
canonicalizer produces Go-identical bytes for synthetic inputs covering
field ordering, omitempty, HTML escaping, and nested envelopes.
"""

from __future__ import annotations

from pipelock_verify._canonical import (
    _is_go_zero,
    canonicalize_action_record,
    canonicalize_receipt,
)


def _minimal_action_record():
    """An action record with every required field populated."""
    return {
        "version": 1,
        "action_id": "test-id",
        "action_type": "read",
        "timestamp": "2026-04-15T12:00:00Z",
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


def test_field_order_matches_go_struct():
    """Canonical output uses Go struct-tag order, not alphabetical."""
    ar = _minimal_action_record()
    canonical = canonicalize_action_record(ar).decode()

    # version comes before action_id, action_id before action_type, etc.
    assert canonical.startswith('{"version":1,"action_id":"test-id","action_type":"read"')
    # chain_prev_hash and chain_seq come near the end, after transport
    assert '"transport":"https","chain_prev_hash":"genesis","chain_seq":0' in canonical


def test_omitempty_drops_empty_string():
    """Empty ``intent`` is dropped (it has omitempty)."""
    ar = _minimal_action_record()
    ar["intent"] = ""
    canonical = canonicalize_action_record(ar).decode()
    assert '"intent"' not in canonical


def test_omitempty_keeps_non_empty_string():
    """Non-empty ``intent`` is included in order."""
    ar = _minimal_action_record()
    ar["intent"] = "create issue"
    canonical = canonicalize_action_record(ar).decode()
    assert '"intent":"create issue"' in canonical
    # intent sits between target and data_classes_in in the struct, so it
    # must come after target and (since data_classes_in is omitted) before
    # side_effect_class.
    target_pos = canonical.index('"target"')
    intent_pos = canonical.index('"intent"')
    side_effect_pos = canonical.index('"side_effect_class"')
    assert target_pos < intent_pos < side_effect_pos


def test_omitempty_drops_empty_list():
    """Empty ``data_classes_in`` is dropped."""
    ar = _minimal_action_record()
    ar["data_classes_in"] = []
    canonical = canonicalize_action_record(ar).decode()
    assert '"data_classes_in"' not in canonical


def test_no_whitespace():
    """Canonical output is compact: no spaces, no newlines."""
    ar = _minimal_action_record()
    canonical = canonicalize_action_record(ar).decode()
    assert " " not in canonical.replace('"target":"https://example.com"', "")
    assert "\n" not in canonical


def test_html_escaping_matches_go():
    """<, >, & are escaped as \\u003c, \\u003e, \\u0026."""
    ar = _minimal_action_record()
    ar["target"] = "https://example.com/a<b>c&d"
    canonical = canonicalize_action_record(ar).decode()
    assert "\\u003c" in canonical
    assert "\\u003e" in canonical
    assert "\\u0026" in canonical
    # Literal characters must not appear — Go would have escaped them.
    assert "<" not in canonical
    assert ">" not in canonical
    assert "&" not in canonical


def test_receipt_envelope_order():
    """Receipt envelope uses version, action_record, signature, signer_key order."""
    receipt = {
        "signer_key": "abcd",
        "signature": "ed25519:00",
        "action_record": _minimal_action_record(),
        "version": 1,
    }
    canonical = canonicalize_receipt(receipt).decode()
    # Expect Go struct order regardless of input dict order.
    assert canonical.startswith('{"version":1,"action_record":{')
    assert canonical.endswith('"signature":"ed25519:00","signer_key":"abcd"}')


def test_unknown_fields_dropped():
    """Fields not in the Go struct are dropped (match json.Marshal behavior).

    Go's json.Unmarshal silently drops unknown keys when loading into the
    struct; json.Marshal never puts them back. Python must do the same, or
    canonical form diverges for round-tripped receipts.
    """
    ar = _minimal_action_record()
    ar["x_vendor_extension"] = "should-be-dropped"
    canonical = canonicalize_action_record(ar).decode()
    assert "x_vendor_extension" not in canonical


def test_is_go_zero_covers_python_types():
    assert _is_go_zero(None)
    assert _is_go_zero("")
    assert _is_go_zero([])
    assert _is_go_zero({})
    assert _is_go_zero(0)
    assert _is_go_zero(0.0)
    assert _is_go_zero(False)
    assert not _is_go_zero("x")
    assert not _is_go_zero([0])
    assert not _is_go_zero({"k": "v"})
    assert not _is_go_zero(1)
    assert not _is_go_zero(True)
