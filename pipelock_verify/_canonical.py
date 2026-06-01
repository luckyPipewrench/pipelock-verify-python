"""Go-compatible JSON canonicalization for action records and receipts.

The signing input for a Pipelock receipt is the SHA-256 of the canonical
JSON encoding of the inner ``ActionRecord``. "Canonical" here means
"byte-identical to what Go's ``encoding/json`` produces when marshalling
the ``receipt.ActionRecord`` struct." That contract is what this module
reproduces. The same rules apply when hashing the full ``Receipt`` envelope
for chain linkage.

What Go does that matters:

* Fields are emitted in **struct declaration order**, not alphabetical.
* Fields tagged ``omitempty`` are dropped when the value is the Go zero value
  (``""`` for strings, empty slice, ``0``, ``false``, nil).
* Compact output: no whitespace between tokens.
* HTML-safe escaping: ``<``, ``>``, ``&``, U+2028, U+2029 are escaped as
  ``\\u003c``, ``\\u003e``, ``\\u0026``, ``\\u2028``, ``\\u2029`` even inside
  strings that would otherwise be valid JSON.

Any deviation from these rules produces different bytes, which produces a
different SHA-256, which fails signature verification. There is no slack.
"""

from __future__ import annotations

import json
from typing import Any

# Field specs are (json_name, has_omitempty, nested_kind). nested_kind is one
# of None, "action_record", "redaction", "shield", or "taint_source" and tells
# the orderer to recurse into a nested object (or, for "taint_source", into
# each element of a nested array) so the nested object's keys are reordered to
# the Go struct order too. Go re-marshals nested structs in declaration order,
# so a verifier that leaves nested object keys in input order recomputes a
# different signing hash whenever the input keys are not already Go-ordered.
#
# ActionRecord fields in Go struct-tag order. Source of truth:
# https://github.com/luckyPipewrench/pipelock/blob/main/internal/receipt/action.go
# The list MUST match that struct's field set, declaration order, and omitempty
# semantics EXACTLY — including parent_action_id, the taint block, the contract
# block, severity, redaction, and shield. Any omitted or reordered field breaks
# signature verification for receipts that carry it.
_ACTION_RECORD_FIELDS: list[tuple[str, bool, str | None]] = [
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
    ("venue", True, None),
    ("jurisdiction", True, None),
    ("rulebook_id", True, None),
    ("remedy_class", True, None),
    ("contestation_window", True, None),
    ("precedent_refs", True, None),
]

# Receipt envelope fields in Go struct-tag order. Source of truth:
# https://github.com/luckyPipewrench/pipelock/blob/main/internal/receipt/receipt.go
_RECEIPT_FIELDS: list[tuple[str, bool, str | None]] = [
    ("version", False, None),
    ("action_record", False, "action_record"),
    ("signature", False, None),
    ("signer_key", False, None),
]

# RedactionSummary fields, Go struct order (receipt.RedactionSummary).
_REDACTION_FIELDS: list[tuple[str, bool, str | None]] = [
    ("profile", True, None),
    ("provider", True, None),
    ("parser", True, None),
    ("total_redactions", True, None),
    ("by_class", True, None),
    ("cache_boundary_kept", True, None),
]

# ShieldSummary fields, Go struct order (receipt.ShieldSummary).
_SHIELD_FIELDS: list[tuple[str, bool, str | None]] = [
    ("pipeline", True, None),
    ("total_rewrites", True, None),
    ("extension_probes", True, None),
    ("tracking_beacons", True, None),
    ("agent_traps", True, None),
    ("fingerprint_shim_injected", True, None),
    ("svg_foreign_objects", True, None),
    ("svg_event_handlers", True, None),
    ("svg_external_references", True, None),
    ("svg_hidden_text", True, None),
    ("svg_animation_injections", True, None),
    ("body_bytes", True, None),
    ("scanned_bytes", True, None),
    ("partial", True, None),
    ("adaptive_signals_recorded", True, None),
    ("adaptive_signal_max_per_body", True, None),
]

# TaintSourceRef fields, Go struct order (session.TaintSourceRef).
_TAINT_SOURCE_FIELDS: list[tuple[str, bool, str | None]] = [
    ("url", False, None),
    ("kind", False, None),
    ("level", False, None),
    ("timestamp", False, None),
    ("receipt_id", True, None),
    ("match_reason", True, None),
]

# Maps a nested_kind tag to its field list (object-valued nests only).
_NESTED_OBJECT_FIELDS: dict[str, list[tuple[str, bool, str | None]]] = {
    "action_record": _ACTION_RECORD_FIELDS,
    "redaction": _REDACTION_FIELDS,
    "shield": _SHIELD_FIELDS,
}


def _is_go_zero(value: Any) -> bool:
    """Return True if ``value`` matches Go's ``omitempty`` zero value.

    Go drops a field tagged ``omitempty`` when the value is the zero value
    for its type: ``""``, empty/nil slice, empty/nil map, ``0``, ``false``,
    or ``nil``. Python equivalents:

    * ``None`` (nil)
    * ``""`` (string zero)
    * ``[]`` (nil or empty slice)
    * ``{}`` (nil or empty map)
    * ``False``
    * ``0`` / ``0.0``
    """
    if value is None:
        return True
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, str):
        return value == ""
    if isinstance(value, (list, tuple, dict)):
        return len(value) == 0
    return False


def _normalize_maps(value: Any) -> Any:
    """Recursively sort the keys of any plain map, matching Go's json.Marshal.

    Go marshals a ``map[string]T`` with keys in sorted order. Struct fields are
    emitted in declaration order (handled by the field-list orderers), but a
    value that is a free-form map — the only one in the schema is
    ``redaction.by_class`` — must have its keys sorted here or it canonicalizes
    differently than Go whenever the input keys are not already sorted. Mirrors
    the TypeScript ``normalizeMaps`` and Rust ``normalize_maps`` helpers.
    """
    if isinstance(value, list):
        return [_normalize_maps(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_maps(value[key]) for key in sorted(value)}
    return value


def _order_object(
    obj: dict[str, Any],
    fields: list[tuple[str, bool, str | None]],
) -> dict[str, Any]:
    """Return a new dict with ``obj``'s keys in Go's canonical struct order.

    Missing fields are skipped. ``omitempty`` fields with zero values are
    dropped. Unknown fields are ignored: Go's ``json.Unmarshal`` would drop
    them, and the re-serialized canonical form should not include them.

    Nested fields recurse so nested object keys are reordered to Go order too:

    * ``"action_record"``/``"redaction"``/``"shield"`` reorder an object value.
    * ``"taint_source"`` reorders each object element of an array value.
    """
    ordered: dict[str, Any] = {}
    for name, omitempty, nested in fields:
        if name not in obj:
            continue
        value = obj[name]
        if omitempty and _is_go_zero(value):
            continue
        if nested == "taint_source" and isinstance(value, list):
            value = [
                _order_object(item, _TAINT_SOURCE_FIELDS) if isinstance(item, dict) else item
                for item in value
            ]
        elif nested in _NESTED_OBJECT_FIELDS and isinstance(value, dict):
            value = _order_object(value, _NESTED_OBJECT_FIELDS[nested])
        else:
            # Non-struct value: sort any free-form map keys to match Go.
            value = _normalize_maps(value)
        ordered[name] = value
    return ordered


def _go_html_escape(serialized: str) -> str:
    """Apply Go's default HTML-safe escaping to a JSON string.

    Go's ``encoding/json`` escapes ``<``, ``>``, ``&`` and the Unicode line
    separators U+2028, U+2029 even inside string values. Python's
    ``json.dumps`` does not. This post-processes the Python output so it
    matches Go byte-for-byte.
    """
    return (
        serialized.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _to_canonical_bytes(obj: Any) -> bytes:
    """Serialize an ordered dict to canonical UTF-8 bytes."""
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return _go_html_escape(raw).encode("utf-8")


def canonicalize_action_record(ar: dict[str, Any]) -> bytes:
    """Return the signing input bytes for an action record.

    The returned bytes are what Go's ``ActionRecord.Canonical()`` produces
    and what gets SHA-256-hashed before Ed25519 signing.
    """
    return _to_canonical_bytes(_order_object(ar, _ACTION_RECORD_FIELDS))


def canonicalize_receipt(receipt: dict[str, Any]) -> bytes:
    """Return the chain-linking bytes for a full receipt envelope.

    The returned bytes are what Go's ``json.Marshal(receipt)`` produces
    and what gets SHA-256-hashed to form the next receipt's ``chain_prev_hash``.
    """
    return _to_canonical_bytes(_order_object(receipt, _RECEIPT_FIELDS))
