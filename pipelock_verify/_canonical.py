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

# ActionRecord fields in Go struct-tag order. Each tuple is
# (json_name, has_omitempty). Source of truth:
# https://github.com/luckyPipewrench/pipelock/blob/main/internal/receipt/action.go
_ACTION_RECORD_FIELDS: list[tuple[str, bool]] = [
    ("version", False),
    ("action_id", False),
    ("action_type", False),
    ("timestamp", False),
    ("principal", False),
    ("actor", False),
    ("delegation_chain", False),
    ("target", False),
    ("intent", True),
    ("data_classes_in", True),
    ("data_classes_out", True),
    ("side_effect_class", False),
    ("reversibility", False),
    ("policy_hash", False),
    ("verdict", False),
    ("transport", False),
    ("method", True),
    ("layer", True),
    ("pattern", True),
    ("request_id", True),
    ("chain_prev_hash", False),
    ("chain_seq", False),
    ("venue", True),
    ("jurisdiction", True),
    ("rulebook_id", True),
    ("remedy_class", True),
    ("contestation_window", True),
    ("precedent_refs", True),
]

# Receipt envelope fields in Go struct-tag order. Source of truth:
# https://github.com/luckyPipewrench/pipelock/blob/main/internal/receipt/receipt.go
_RECEIPT_FIELDS: list[tuple[str, bool]] = [
    ("version", False),
    ("action_record", False),
    ("signature", False),
    ("signer_key", False),
]


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


def _order_action_record(ar: dict[str, Any]) -> dict[str, Any]:
    """Return a new dict with ActionRecord fields in Go's canonical order.

    Missing fields are skipped. ``omitempty`` fields with zero values are
    dropped. Unknown fields are ignored: Go's ``json.Unmarshal`` would drop
    them, and the re-serialized canonical form should not include them.
    """
    ordered: dict[str, Any] = {}
    for name, omitempty in _ACTION_RECORD_FIELDS:
        if name not in ar:
            continue
        value = ar[name]
        if omitempty and _is_go_zero(value):
            continue
        ordered[name] = value
    return ordered


def _order_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Return a new dict with Receipt fields in Go's canonical order.

    The nested ``action_record`` is also reordered, so this function alone
    is enough to produce canonical bytes for the full envelope (used when
    computing chain prev_hash linkage).
    """
    ordered: dict[str, Any] = {}
    for name, omitempty in _RECEIPT_FIELDS:
        if name not in receipt:
            continue
        value = receipt[name]
        if omitempty and _is_go_zero(value):
            continue
        if name == "action_record" and isinstance(value, dict):
            value = _order_action_record(value)
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
    return _to_canonical_bytes(_order_action_record(ar))


def canonicalize_receipt(receipt: dict[str, Any]) -> bytes:
    """Return the chain-linking bytes for a full receipt envelope.

    The returned bytes are what Go's ``json.Marshal(receipt)`` produces
    and what gets SHA-256-hashed to form the next receipt's ``chain_prev_hash``.
    """
    return _to_canonical_bytes(_order_receipt(receipt))
