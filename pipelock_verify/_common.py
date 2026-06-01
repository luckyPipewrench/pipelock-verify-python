"""Shared primitives used by both v1 and v2 receipt verification.

This module is intentionally a leaf: it has no intra-package imports.
``_verify`` (v1) and ``_evidence`` (v2) both depend on it, which lets each
module reach the symbols it needs without importing the other and
forming an import cycle.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

# RFC 3339 / time.RFC3339Nano shape check. Go's time.Time.UnmarshalJSON
# accepts:
#
#   2006-01-02T15:04:05Z                        (no fractional seconds)
#   2006-01-02T15:04:05.999999999Z              (up to 9 fractional digits)
#   2006-01-02T15:04:05.999999999+07:00         (numeric offset)
#
# It rejects anything else, including lower-case "t"/"z", missing timezone,
# or non-numeric content. The regex below enforces the shape; a follow-up
# datetime.fromisoformat() call catches semantic errors like month 13 or
# day 32. Both checks must pass or the timestamp is invalid.
_RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")


def _is_valid_rfc3339(value: Any) -> bool:
    """Return True if value parses as an RFC 3339 timestamp Go would accept.

    Go's ``time.RFC3339Nano`` allows up to 9 fractional digits (nanoseconds).
    Python's ``datetime.fromisoformat`` tops out at microsecond precision
    (6 fractional digits) and the ``Z`` suffix only parses natively on 3.11+.
    We handle both differences here so valid Go timestamps verify on 3.9-3.13.
    """
    if not isinstance(value, str):
        return False
    if not _RFC3339_RE.match(value):
        return False
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    # Truncate fractional seconds to 6 digits so fromisoformat accepts
    # Go's nanosecond timestamps on Python 3.9/3.10. The regex above has
    # already validated the overall shape, so we know there is at most one
    # ``.`` before the timezone offset.
    match = re.match(
        r"^(?P<prefix>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"(?:\.(?P<frac>\d{1,9}))?"
        r"(?P<offset>[+-]\d{2}:\d{2})$",
        candidate,
    )
    if match is None:
        return False
    prefix = match.group("prefix")
    frac = match.group("frac") or ""
    offset = match.group("offset")
    truncated = f"{prefix}.{frac[:6]}{offset}" if frac else f"{prefix}{offset}"
    try:
        datetime.fromisoformat(truncated)
    except ValueError:
        return False
    return True


class InvalidReceiptError(Exception):
    """Raised when a receipt cannot be parsed as JSON at all."""


class DuplicateKeyError(InvalidReceiptError):
    """Raised when a receipt JSON object contains a duplicate key.

    ``json.loads`` silently keeps the last value for a duplicate key, so
    ``{"verdict": "allow", "verdict": "block"}`` would decode as ``"block"``
    with no error. That is a parser-differential smuggling vector: a display or
    log layer reading the first occurrence sees a value different from the one
    the signature was verified against. The verify path rejects such input
    before signature verification.
    """


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that rejects any duplicate key in an object.

    ``json.loads`` invokes this for every object at every nesting depth with
    the full ordered list of (key, value) pairs *before* it collapses
    duplicates, so a duplicate at any depth is caught.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise DuplicateKeyError(f"duplicate object key: {key!r}")
        seen.add(key)
    return dict(pairs)


# Shared cross-language receipt-nesting cap. The Go and TypeScript verifiers
# enforce the same value and Rust inherits it from serde_json's default
# recursion limit, so all four reject input nested beyond this depth. Receipts
# nest ~4 levels, so honest input is never affected.
_MAX_NESTING_DEPTH = 128


def _exceeds_max_depth(text: str) -> bool:
    """Return True if text nests objects/arrays beyond _MAX_NESTING_DEPTH.

    A cheap string-aware scan (string contents are skipped) run before
    json.loads so deeply nested ARRAYS — which never reach object_pairs_hook and
    would otherwise raise CPython's RecursionError — are rejected at the same
    depth as the other verifiers, rather than at the interpreter's stack limit.
    """
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > _MAX_NESTING_DEPTH:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def loads_no_duplicate_keys(text: str | bytes) -> Any:
    """``json.loads`` that rejects duplicate object keys at any nesting depth.

    Also rejects input nested beyond the shared cross-language depth cap. That
    bound is enforced before json.loads so deeply nested arrays cannot make
    CPython raise ``RecursionError`` (which is not a ``JSONDecodeError`` and
    would otherwise escape the verify path's handling and crash the caller); a
    ``RecursionError`` backstop covers any residual case.
    """
    scan_text = text.decode("utf-8") if isinstance(text, bytes) else text
    if _exceeds_max_depth(scan_text):
        raise InvalidReceiptError("JSON nesting too deep")
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except RecursionError as exc:
        raise InvalidReceiptError("JSON nesting too deep") from exc
