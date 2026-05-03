"""Well-known HTTP message signatures directory fetch helper.

Implements the client side of ``/.well-known/http-message-signatures-directory``
(RFC 9421). The directory is a JSON keyset served at the well-known path on
any Pipelock instance.

Wire format (from ``internal/envelope/directory.go``):

.. code-block:: json

    {
        "keys": [
            {
                "keyid": "pipelock-mediation-prod",
                "alg": "ed25519",
                "public_key": "<hex-encoded 32-byte Ed25519 public key>",
                "use": "pipelock-mediation"
            }
        ]
    }

No new dependencies: uses ``urllib.request`` from the standard library.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any

WELL_KNOWN_PATH = "/.well-known/http-message-signatures-directory"


class DirectoryFetchError(Exception):
    """Raised when the directory cannot be fetched or parsed."""


@dataclass
class DirectoryKey:
    """A single key entry from the well-known directory."""

    keyid: str
    algorithm: str
    public_key: str  # hex-encoded Ed25519 public key
    use: str


@dataclass
class Directory:
    """Parsed well-known directory keyset."""

    keys: list[DirectoryKey] = field(default_factory=list)

    def get_key(self, keyid: str) -> DirectoryKey | None:
        """Look up a key by keyid. Returns None if not found."""
        for k in self.keys:
            if k.keyid == keyid:
                return k
        return None

    def public_key_hex(self, keyid: str | None = None) -> str | None:
        """Return the hex public key for a given keyid, or the first key if None.

        Convenience method for callers that want a single trust anchor.
        """
        if keyid is not None:
            k = self.get_key(keyid)
            return k.public_key if k else None
        if self.keys:
            return self.keys[0].public_key
        return None


def fetch_directory(
    host: str,
    *,
    timeout: float = 10.0,
    scheme: str = "https",
) -> Directory:
    """Fetch and parse the well-known directory from a Pipelock host.

    Args:
        host: Hostname (and optional port) of the Pipelock instance,
            e.g. ``"pipelab.org"`` or ``"localhost:8888"``.
        timeout: HTTP request timeout in seconds.
        scheme: URL scheme. Defaults to ``"https"``.

    Returns:
        A :class:`Directory` with the parsed keyset.

    Raises:
        DirectoryFetchError: On network error, non-200 response, or
            malformed JSON.
    """
    # Restrict to HTTP(S) so a caller-controlled scheme cannot reach
    # urllib's file:// handler and read arbitrary local files. The
    # host check rejects path separators that would let a caller
    # smuggle path components into the host slot.
    if scheme.lower() not in {"https", "http"}:
        raise DirectoryFetchError(f"unsupported URL scheme: {scheme!r}")
    if "/" in host or "\\" in host:
        raise DirectoryFetchError("host must not contain path separators")
    url = f"{scheme}://{host}{WELL_KNOWN_PATH}"
    req = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise DirectoryFetchError(f"directory fetch returned HTTP {resp.status}")
            body = resp.read()
    except DirectoryFetchError:
        raise
    except Exception as exc:
        raise DirectoryFetchError(f"fetching {url}: {exc}") from exc

    return parse_directory(body)


def parse_directory(data: bytes | str | dict[str, Any]) -> Directory:
    """Parse a well-known directory from raw JSON bytes, string, or dict.

    Args:
        data: The directory JSON.

    Returns:
        A :class:`Directory`.

    Raises:
        DirectoryFetchError: On malformed JSON or missing required fields.
    """
    if isinstance(data, dict):
        parsed = data
    else:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as exc:
            raise DirectoryFetchError(f"parsing directory JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise DirectoryFetchError("directory must be a JSON object")

    raw_keys = parsed.get("keys")
    if not isinstance(raw_keys, list):
        raise DirectoryFetchError("directory 'keys' must be a JSON array")

    keys: list[DirectoryKey] = []
    for i, entry in enumerate(raw_keys):
        if not isinstance(entry, dict):
            raise DirectoryFetchError(f"directory keys[{i}] must be a JSON object")

        keyid = entry.get("keyid")
        if not isinstance(keyid, str) or not keyid:
            raise DirectoryFetchError(f"directory keys[{i}].keyid must be a non-empty string")

        alg = entry.get("alg")
        if not isinstance(alg, str) or not alg:
            raise DirectoryFetchError(f"directory keys[{i}].alg must be a non-empty string")

        public_key = entry.get("public_key")
        if not isinstance(public_key, str) or not public_key:
            raise DirectoryFetchError(f"directory keys[{i}].public_key must be a non-empty string")

        # Validate hex encoding.
        try:
            key_bytes = bytes.fromhex(public_key)
        except ValueError as exc:
            raise DirectoryFetchError(f"directory keys[{i}].public_key invalid hex: {exc}") from exc
        if len(key_bytes) != 32:
            raise DirectoryFetchError(
                f"directory keys[{i}].public_key must be 32 bytes, got {len(key_bytes)}"
            )

        use = entry.get("use")
        if not isinstance(use, str) or not use:
            raise DirectoryFetchError(f"directory keys[{i}].use must be a non-empty string")

        keys.append(DirectoryKey(keyid=keyid, algorithm=alg, public_key=public_key, use=use))

    return Directory(keys=keys)
