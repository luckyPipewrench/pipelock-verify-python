"""Old-key-signed receipt rotation endorsement verification."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._common import InvalidReceiptError, _is_valid_rfc3339, loads_no_duplicate_keys

_VERSION = 1
_DOMAIN = b"pipelock-rotation-endorsement-v1\x00"
_SIGNATURE_PREFIX = "ed25519:"
_MAX_BYTES = 64 << 10
_FIELDS = frozenset(
    {
        "version",
        "session_id",
        "prior_signer_key",
        "prior_final_seq",
        "prior_tail_hash",
        "new_signer_key",
        "rotated_at",
        "endorsement",
    }
)
_LOWER_HEX_32 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{0,8}[1-9])?Z$"
)


@dataclass(frozen=True)
class RotationEndorsement:
    """A retiring receipt key's authorization of its successor."""

    version: int
    session_id: str
    prior_signer_key: str
    prior_final_seq: int
    prior_tail_hash: str
    new_signer_key: str
    rotated_at: str
    endorsement: str


def _normalize_go_string(value: str) -> str:
    """Replace lone UTF-16 surrogates as Go encoding/json does."""
    out: list[str] = []
    index = 0
    while index < len(value):
        code = ord(value[index])
        if 0xD800 <= code <= 0xDBFF:
            if index + 1 < len(value) and 0xDC00 <= ord(value[index + 1]) <= 0xDFFF:
                high = code - 0xD800
                low = ord(value[index + 1]) - 0xDC00
                out.append(chr(0x10000 + high * 0x400 + low))
                index += 2
                continue
            out.append("\ufffd")
        elif 0xDC00 <= code <= 0xDFFF:
            out.append("\ufffd")
        else:
            out.append(value[index])
        index += 1
    return "".join(out)


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidReceiptError(f"rotation endorsement {field} is invalid")
    return _normalize_go_string(value)


def _require_hex(value: Any, field: str) -> str:
    text = _require_string(value, field)
    if _LOWER_HEX_32.fullmatch(text) is None:
        raise InvalidReceiptError(f"rotation endorsement {field} is invalid")
    return text


def _decode(value: dict[str, Any]) -> RotationEndorsement:
    unknown = set(value) - _FIELDS
    if unknown:
        raise InvalidReceiptError(
            f"rotation endorsement contains unknown field {sorted(unknown)[0]}"
        )
    missing = _FIELDS - set(value)
    if missing:
        raise InvalidReceiptError(
            f"rotation endorsement is missing required field {sorted(missing)[0]}"
        )
    version = value["version"]
    if isinstance(version, bool) or version != _VERSION:
        raise InvalidReceiptError(f"unsupported rotation endorsement version {version!r}")
    prior_final_seq = value["prior_final_seq"]
    if (
        isinstance(prior_final_seq, bool)
        or not isinstance(prior_final_seq, int)
        or not 0 <= prior_final_seq <= 2**64 - 1
    ):
        raise InvalidReceiptError("rotation endorsement prior_final_seq is invalid")
    session_id = _require_string(value["session_id"], "session_id")
    if not session_id.strip():
        raise InvalidReceiptError("rotation endorsement session_id is empty")
    prior_key = _require_hex(value["prior_signer_key"], "prior_signer_key")
    new_key = _require_hex(value["new_signer_key"], "new_signer_key")
    if prior_key == new_key:
        raise InvalidReceiptError("rotation endorsement successor key must differ from prior key")
    rotated_at = _require_string(value["rotated_at"], "rotated_at")
    if _CANONICAL_UTC.fullmatch(rotated_at) is None or not _is_valid_rfc3339(rotated_at):
        raise InvalidReceiptError(
            "rotation endorsement rotated_at must be canonical UTC RFC3339Nano"
        )
    return RotationEndorsement(
        version=_VERSION,
        session_id=session_id,
        prior_signer_key=prior_key,
        prior_final_seq=prior_final_seq,
        prior_tail_hash=_require_hex(value["prior_tail_hash"], "prior_tail_hash"),
        new_signer_key=new_key,
        rotated_at=rotated_at,
        endorsement=_require_string(value["endorsement"], "signature"),
    )


def _canonical_bytes(endorsement: RotationEndorsement) -> bytes:
    ordered = {
        "version": endorsement.version,
        "session_id": endorsement.session_id,
        "prior_signer_key": endorsement.prior_signer_key,
        "prior_final_seq": endorsement.prior_final_seq,
        "prior_tail_hash": endorsement.prior_tail_hash,
        "new_signer_key": endorsement.new_signer_key,
        "rotated_at": endorsement.rotated_at,
    }
    encoded = json.dumps(
        ordered,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    encoded = (
        encoded.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    return encoded.encode()


def verify_rotation_endorsement(
    source: RotationEndorsement | dict[str, Any] | str | bytes,
) -> RotationEndorsement:
    """Strictly parse and verify one rotation endorsement."""
    if isinstance(source, RotationEndorsement):
        endorsement = _decode(vars(source))
    else:
        if isinstance(source, bytes):
            if len(source) > _MAX_BYTES:
                raise InvalidReceiptError(f"rotation endorsement exceeds {_MAX_BYTES} bytes")
            try:
                text = source.decode("utf-8")
                parsed = loads_no_duplicate_keys(text)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise InvalidReceiptError(f"unmarshal rotation endorsement: {exc}") from exc
        elif isinstance(source, str):
            if len(source.encode()) > _MAX_BYTES:
                raise InvalidReceiptError(f"rotation endorsement exceeds {_MAX_BYTES} bytes")
            try:
                parsed = loads_no_duplicate_keys(source)
            except json.JSONDecodeError as exc:
                raise InvalidReceiptError(f"unmarshal rotation endorsement: {exc}") from exc
        elif isinstance(source, dict):
            parsed = source
        else:
            raise InvalidReceiptError("rotation endorsement must be a JSON object")
        if not isinstance(parsed, dict):
            raise InvalidReceiptError("rotation endorsement must be a JSON object")
        endorsement = _decode(parsed)
    if not endorsement.endorsement.startswith(_SIGNATURE_PREFIX):
        raise InvalidReceiptError(
            f"invalid endorsement signature format: missing {_SIGNATURE_PREFIX} prefix"
        )
    try:
        signature = bytes.fromhex(endorsement.endorsement[len(_SIGNATURE_PREFIX) :])
    except ValueError as exc:
        raise InvalidReceiptError("invalid endorsement signature") from exc
    if len(signature) != 64:
        raise InvalidReceiptError("invalid endorsement signature")
    digest = hashlib.sha256(_DOMAIN + _canonical_bytes(endorsement)).digest()
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(endorsement.prior_signer_key))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise InvalidReceiptError("rotation endorsement signer key is invalid") from exc
    try:
        public_key.verify(signature, digest)
    except InvalidSignature as exc:
        raise InvalidReceiptError("rotation endorsement signature verification failed") from exc
    return endorsement


def load_rotation_endorsement(path: str | Path) -> RotationEndorsement:
    """Read and verify one bounded endorsement file."""
    file = Path(path)
    try:
        with file.open("rb") as handle:
            data = handle.read(_MAX_BYTES + 1)
    except OSError as exc:
        raise InvalidReceiptError(f"read rotation endorsement: {exc}") from exc
    return verify_rotation_endorsement(data)
