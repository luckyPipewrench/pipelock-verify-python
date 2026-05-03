"""Shared primitives used by both v1 and v2 receipt verification.

This module is intentionally a leaf: it has no intra-package imports.
``_verify`` (v1) and ``_evidence`` (v2) both depend on it, which lets each
module reach the symbols it needs without importing the other and
forming an import cycle.
"""

from __future__ import annotations

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
