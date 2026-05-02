"""RFC 8785 JSON Canonicalization Scheme (JCS) for EvidenceReceipt v2.

EvidenceReceipt v2 uses JCS over typed structures, NOT Go's encoding/json
byte order. The signing preimage is:

    jcs(receipt_with_signature_zeroed_out)

JCS rules (RFC 8785):
- Objects: keys sorted lexicographically by codepoint (Unicode code point order).
- Arrays: preserve insertion order.
- Strings: NFC-normalized, then JSON-escaped per ECMA-262.
- Numbers: integer-only (floats rejected per the design doc).
- No whitespace between tokens.
- Booleans: literal ``true`` / ``false``.
- Null: literal ``null``.

This module mirrors ``internal/contract/canonicalize.go`` in Pipelock.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any


class JCSError(Exception):
    """Raised on canonicalization failure (float, invalid UTF-8, etc.)."""


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785 JCS canonical bytes for a parsed JSON value.

    Args:
        value: A parsed JSON tree (dict, list, str, int, float, bool, None).
            Floats are rejected. ``json.loads`` with ``parse_int=int`` and
            ``parse_float=_reject_float`` is the expected input path.

    Returns:
        UTF-8 bytes of the JCS-canonical JSON.

    Raises:
        JCSError: On float, non-string map key, or other unsupported type.
    """
    parts: list[str] = []
    _canonicalize_into(parts, value)
    return "".join(parts).encode("utf-8")


def _canonicalize_into(parts: list[str], value: Any) -> None:
    if value is None:
        parts.append("null")
    elif isinstance(value, bool):
        # Must check bool before int because bool is a subclass of int.
        parts.append("true" if value else "false")
    elif isinstance(value, int):
        parts.append(str(value))
    elif isinstance(value, float):
        raise JCSError("float not allowed in JCS canonicalization; use decimal string")
    elif isinstance(value, str):
        nfc = unicodedata.normalize("NFC", value)
        parts.append(json.dumps(nfc, ensure_ascii=False))
    elif isinstance(value, list):
        parts.append("[")
        for i, item in enumerate(value):
            if i > 0:
                parts.append(",")
            _canonicalize_into(parts, item)
        parts.append("]")
    elif isinstance(value, dict):
        # Sort keys lexicographically by Unicode codepoint (NFC-normalized).
        nfc_pairs: list[tuple[str, str, Any]] = []
        for k, v in value.items():
            if not isinstance(k, str):
                raise JCSError(f"map key must be string, got {type(k).__name__}")
            nfc_key = unicodedata.normalize("NFC", k)
            nfc_pairs.append((nfc_key, k, v))
        nfc_pairs.sort(key=lambda t: t[0])
        # Reject NFC collisions (two distinct keys that normalize to the same form).
        for i in range(1, len(nfc_pairs)):
            if nfc_pairs[i][0] == nfc_pairs[i - 1][0] and nfc_pairs[i][1] != nfc_pairs[i - 1][1]:
                raise JCSError(
                    f"duplicate key after NFC normalization: "
                    f"{nfc_pairs[i - 1][1]!r} and {nfc_pairs[i][1]!r}"
                )
        parts.append("{")
        for i, (nfc_key, _orig_key, val) in enumerate(nfc_pairs):
            if i > 0:
                parts.append(",")
            parts.append(json.dumps(nfc_key, ensure_ascii=False))
            parts.append(":")
            _canonicalize_into(parts, val)
        parts.append("}")
    else:
        raise JCSError(f"unsupported type for JCS: {type(value).__name__}")


def parse_json_strict(data: bytes | str) -> Any:
    """Parse JSON with strict semantics matching Go's contract.ParseJSONStrict.

    - ``json.Decoder`` with ``parse_int=int`` and floats rejected.
    - Duplicate keys in objects are detected by Python's ``json.loads``
      (last-wins); we do a manual check via ``json.JSONDecoder`` with
      ``object_pairs_hook``.
    - Trailing tokens after the value are rejected.

    Returns:
        The parsed JSON tree.

    Raises:
        JCSError: On duplicate keys, trailing tokens, or float values.
    """
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JCSError(f"JSON parse error: {exc}") from exc

    # Use object_pairs_hook to detect duplicate keys. raw_decode does
    # not skip leading whitespace on its own, so strip it ourselves and
    # carry the offset forward for the trailing-token check.
    decoder = json.JSONDecoder(object_pairs_hook=_check_duplicate_keys)
    stripped = data.lstrip()
    ws_prefix = len(data) - len(stripped)
    try:
        value, idx = decoder.raw_decode(stripped)
    except json.JSONDecodeError as exc:
        raise JCSError(f"JSON parse error: {exc}") from exc
    idx += ws_prefix

    # Check for trailing non-whitespace.
    remaining = data[idx:].strip()
    if remaining:
        raise JCSError(f"trailing tokens after JSON value: {remaining[:50]!r}")

    # Walk the tree and reject any float values.
    _reject_floats_in_tree(value)

    return value


def _check_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """object_pairs_hook that rejects duplicate keys."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JCSError(f"duplicate key in JSON object: {key!r}")
        result[key] = value
    return result


def _reject_floats_in_tree(value: Any) -> None:
    """Walk a parsed JSON tree and raise on any float value."""
    if isinstance(value, float):
        raise JCSError("float not allowed in JCS canonicalization; use decimal string")
    if isinstance(value, dict):
        for v in value.values():
            _reject_floats_in_tree(v)
    elif isinstance(value, list):
        for item in value:
            _reject_floats_in_tree(item)
