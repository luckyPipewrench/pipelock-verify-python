"""Core receipt and chain verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._canonical import canonicalize_action_record, canonicalize_receipt
from ._common import InvalidReceiptError as InvalidReceiptError
from ._common import _is_valid_rfc3339 as _is_valid_rfc3339

# Wire format constants — keep in sync with internal/receipt/receipt.go.
_RECEIPT_VERSION = 1
_ACTION_RECORD_VERSION = 1
_SIGNATURE_PREFIX = "ed25519:"
_GENESIS_HASH = "genesis"

# Ed25519 sizes (RFC 8032): 32-byte public key, 64-byte signature.
_PUBLIC_KEY_LEN = 32
_SIGNATURE_LEN = 64

# Flight-recorder entry type for receipts. Matches
# internal/receipt/emitter.go recorderEntryType.
_RECORDER_ENTRY_TYPE = "action_receipt"

# Valid action_type enum values. Matches the allActionTypes map in
# internal/receipt/action.go. A verifier that does not enforce this set
# will accept Go-rejected receipts (e.g. action_type: "bogus"), which
# breaks cross-implementation agreement. Order mirrors the Go source.
_VALID_ACTION_TYPES = frozenset(
    {
        "read",
        "derive",
        "write",
        "delegate",
        "authorize",
        "spend",
        "commit",
        "actuate",
        "unclassified",
    }
)

@dataclass
class VerifyResult:
    """Outcome of verifying a single receipt.

    ``valid`` is the only field guaranteed to be set. Descriptive fields
    are populated on success (and may be populated on some failures) for
    diagnostic output. ``error`` holds a short reason string on failure.
    """

    valid: bool
    error: str | None = None
    action_id: str | None = None
    action_type: str | None = None
    verdict: str | None = None
    target: str | None = None
    transport: str | None = None
    signer_key: str | None = None
    chain_seq: int | None = None
    chain_prev_hash: str | None = None
    timestamp: str | None = None


@dataclass
class ChainResult:
    """Outcome of verifying a receipt chain.

    Mirrors ``receipt.ChainResult`` in the Go implementation: on break,
    ``broken_at_seq`` identifies where the chain failed, and ``error``
    describes why. On success, ``root_hash`` is the hash of the final
    receipt, suitable for publishing as a transcript root.
    """

    valid: bool
    error: str | None = None
    broken_at_seq: int | None = None
    receipt_count: int = 0
    final_seq: int | None = None
    root_hash: str | None = None
    start_time: str | None = None
    end_time: str | None = None


def verify(
    source: str | bytes | dict[str, Any],
    public_key_hex: str | None = None,
) -> VerifyResult:
    """Verify a single action receipt.

    Args:
        source: Receipt as a JSON string, UTF-8 bytes, or a pre-parsed dict.
        public_key_hex: Optional trust anchor. When supplied, the receipt's
            ``signer_key`` field must match this value (hex-encoded 32-byte
            Ed25519 public key). When omitted, the embedded ``signer_key``
            is trusted.

    Returns:
        A :class:`VerifyResult`. ``result.valid`` is ``True`` only when the
        signature verifies and every structural check passes.
    """
    try:
        parsed = _parse_receipt(source)
    except json.JSONDecodeError as exc:
        return VerifyResult(valid=False, error=f"parsing receipt: {exc}")
    except InvalidReceiptError as exc:
        return VerifyResult(valid=False, error=str(exc))

    # Transparently unwrap a flight-recorder entry wrapper if present so
    # callers can feed either bare receipt JSON or an entry dump.
    try:
        receipt = _extract_receipt(parsed)
    except InvalidReceiptError as exc:
        return VerifyResult(valid=False, error=str(exc))
    if receipt is None:
        return VerifyResult(
            valid=False, error="flight-recorder entry does not carry an action receipt"
        )

    # Version routing: dispatch on record_type field.
    record_type = receipt.get("record_type")
    if record_type == "evidence_receipt_v2":
        from ._evidence import verify_evidence as _verify_v2

        v2_result = _verify_v2(receipt, public_key_hex=public_key_hex)
        # Wrap EvidenceVerifyResult into a VerifyResult for backward compat.
        return VerifyResult(
            valid=v2_result.valid,
            error=v2_result.error,
            action_id=v2_result.event_id,
            action_type=v2_result.payload_kind,
            verdict=None,
            target=None,
            transport=None,
            signer_key=v2_result.signer_key_id,
            chain_seq=v2_result.chain_seq,
            chain_prev_hash=v2_result.chain_prev_hash,
            timestamp=v2_result.timestamp,
        )
    if record_type is not None and record_type not in ("action_receipt_v1", None):
        return VerifyResult(
            valid=False,
            error=f"unknown record_type: {record_type!r}",
        )

    return _verify_receipt_dict(receipt, public_key_hex)


def verify_chain(
    jsonl_path: str | Path,
    public_key_hex: str | None = None,
) -> ChainResult:
    """Verify a receipt chain from a flight recorder JSONL file.

    Args:
        jsonl_path: Path to a JSONL file with one receipt per line. Empty
            lines are ignored.
        public_key_hex: Optional trust anchor. When omitted, the
            ``signer_key`` of the first receipt is taken as the expected
            key and every subsequent receipt must share it. This matches
            the Go ``VerifyChain`` signer-consistency check.

    Returns:
        A :class:`ChainResult`. On failure, ``broken_at_seq`` and ``error``
        locate the first receipt that failed.
    """
    try:
        receipts = _read_jsonl(Path(jsonl_path))
    except FileNotFoundError as exc:
        return ChainResult(valid=False, error=f"reading file: {exc}")
    except json.JSONDecodeError as exc:
        return ChainResult(valid=False, error=f"parsing JSONL: {exc}")
    except InvalidReceiptError as exc:
        # _read_jsonl raises this when a line parses as JSON but doesn't
        # look like a receipt or a flight-recorder entry. Surface it as a
        # normal failure result instead of propagating a raw exception.
        return ChainResult(valid=False, error=f"parsing JSONL: {exc}")

    return _verify_chain_list(receipts, public_key_hex)


# ---- internals ----


def _parse_receipt(source: str | bytes | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    if isinstance(source, bytes):
        source = source.decode("utf-8")
    if not isinstance(source, str):
        raise InvalidReceiptError(
            f"unsupported source type {type(source).__name__}; expected str, bytes, or dict"
        )
    parsed = json.loads(source)
    if not isinstance(parsed, dict):
        raise InvalidReceiptError("receipt must be a JSON object")
    return parsed


def _extract_receipt(parsed: dict[str, Any]) -> dict[str, Any] | None:
    """Pull a receipt dict out of a parsed JSONL line.

    Accepts two formats:

    1. **Bare receipt** — the top-level object already has ``action_record``
       and ``signature``. Returned as-is.
    2. **Flight-recorder entry** — a wrapper with ``type == "action_receipt"``
       and the receipt sitting in ``detail`` (either as an object or as a
       JSON-encoded string, since Go emits it via ``json.RawMessage``).

    Returns ``None`` for flight-recorder entries whose type is not a
    receipt (checkpoints, other event types) so ``_read_jsonl`` can skip
    them without aborting the chain.
    """
    # Flight-recorder entry.
    if "type" in parsed and "detail" in parsed:
        if parsed.get("type") != _RECORDER_ENTRY_TYPE:
            return None
        detail = parsed["detail"]
        if isinstance(detail, dict):
            return detail
        if isinstance(detail, (str, bytes)):
            decoded = json.loads(detail)
            if not isinstance(decoded, dict):
                raise InvalidReceiptError("flight-recorder detail JSON did not decode to an object")
            return decoded
        raise InvalidReceiptError(
            f"flight-recorder detail has unexpected type {type(detail).__name__}"
        )

    # Bare v1 receipt (ActionReceipt).
    if "action_record" in parsed and "signature" in parsed:
        return parsed

    # Bare v2 receipt (EvidenceReceipt): identified by record_type field.
    if "record_type" in parsed and "payload" in parsed:
        return parsed

    raise InvalidReceiptError("unrecognized JSONL line: not a receipt or flight-recorder entry")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    receipts: list[dict[str, Any]] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise json.JSONDecodeError(f"line {lineno}: {exc.msg}", exc.doc, exc.pos) from exc
        if not isinstance(parsed, dict):
            raise json.JSONDecodeError(f"line {lineno}: JSONL entry must be a JSON object", line, 0)
        receipt = _extract_receipt(parsed)
        if receipt is None:
            # Non-receipt recorder entry (checkpoint, other event). Skip
            # instead of failing the whole chain — matches Go ExtractReceipts.
            continue
        receipts.append(receipt)
    return receipts


def _verify_receipt_dict(
    receipt: dict[str, Any],
    expected_key_hex: str | None,
) -> VerifyResult:
    version = receipt.get("version")
    if version != _RECEIPT_VERSION:
        return VerifyResult(
            valid=False,
            error=(f"unsupported receipt version {version} (expected {_RECEIPT_VERSION})"),
        )

    action_record = receipt.get("action_record")
    if not isinstance(action_record, dict):
        return VerifyResult(valid=False, error="missing or invalid action_record")

    ar_version = action_record.get("version")
    if ar_version != _ACTION_RECORD_VERSION:
        return VerifyResult(
            valid=False,
            error=(
                f"unsupported action_record version {ar_version} "
                f"(expected {_ACTION_RECORD_VERSION})"
            ),
        )

    # Match internal/receipt/action.go Validate() exactly. Go's error order
    # and messages are part of the cross-implementation contract:
    #
    #   1. action_id presence          -> "action_id is required"
    #   2. action_type enum membership -> 'invalid action_type "<value>"'
    #      (rejects both empty "" and any non-enum value with the same
    #      wording; the required-field sweep does NOT cover action_type)
    #   3. timestamp presence          -> "timestamp is required"
    #   4. target presence             -> "target is required"
    #   5. verdict presence            -> "verdict is required"
    #   6. transport presence          -> "transport is required"
    #
    # Timestamp validity is enforced BEFORE the signature check because Go
    # parses the receipt into a typed struct first; a malformed timestamp
    # there fails json.Unmarshal and never reaches signature verification.
    # Python parses into a dict, so we have to replay the same check
    # manually or an attacker can ship "timestamp": "not-a-time" with a
    # valid signature over the canonical garbage and Python will accept it.
    if not action_record.get("action_id"):
        return VerifyResult(valid=False, error="invalid action record: action_id is required")

    action_type = action_record.get("action_type", "")
    if action_type not in _VALID_ACTION_TYPES:
        return VerifyResult(
            valid=False,
            error=f'invalid action record: invalid action_type "{action_type}"',
        )

    timestamp = action_record.get("timestamp")
    if not timestamp:
        return VerifyResult(valid=False, error="invalid action record: timestamp is required")
    if not _is_valid_rfc3339(timestamp):
        # Go surfaces this as a json.Unmarshal error; Python surfaces it as
        # its own diagnostic so the fix point is obvious. The net effect —
        # "signed receipt with a bogus timestamp is rejected" — matches.
        return VerifyResult(
            valid=False,
            error=(f'unmarshal receipt: invalid RFC 3339 timestamp "{timestamp}"'),
        )

    for required in ("target", "verdict", "transport"):
        if not action_record.get(required):
            return VerifyResult(
                valid=False,
                error=f"invalid action record: {required} is required",
            )

    signature_str = receipt.get("signature", "")
    if not signature_str:
        return VerifyResult(valid=False, error="receipt has no signature")
    if not isinstance(signature_str, str) or not signature_str.startswith(_SIGNATURE_PREFIX):
        return VerifyResult(
            valid=False,
            error=f"invalid signature format: missing {_SIGNATURE_PREFIX} prefix",
        )

    signer_key_hex = receipt.get("signer_key", "")
    if not signer_key_hex:
        return VerifyResult(valid=False, error="receipt has no signer_key")

    if expected_key_hex and signer_key_hex != expected_key_hex:
        return VerifyResult(
            valid=False,
            error=(f"signer_key {signer_key_hex} does not match expected key {expected_key_hex}"),
        )

    sig_hex = signature_str[len(_SIGNATURE_PREFIX) :]
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
        return VerifyResult(valid=False, error=f"decoding signature: {exc}")
    if len(sig_bytes) != _SIGNATURE_LEN:
        return VerifyResult(
            valid=False,
            error=(f"invalid signature length: got {len(sig_bytes)}, want {_SIGNATURE_LEN}"),
        )

    try:
        pub_key_bytes = bytes.fromhex(signer_key_hex)
    except ValueError as exc:
        return VerifyResult(valid=False, error=f"decoding signer_key: {exc}")
    if len(pub_key_bytes) != _PUBLIC_KEY_LEN:
        return VerifyResult(
            valid=False,
            error=(f"invalid signer_key length: got {len(pub_key_bytes)}, want {_PUBLIC_KEY_LEN}"),
        )

    canonical = canonicalize_action_record(action_record)
    signing_hash = hashlib.sha256(canonical).digest()

    try:
        Ed25519PublicKey.from_public_bytes(pub_key_bytes).verify(sig_bytes, signing_hash)
    except InvalidSignature:
        return VerifyResult(valid=False, error="signature verification failed")

    return VerifyResult(
        valid=True,
        action_id=action_record.get("action_id"),
        action_type=action_record.get("action_type"),
        verdict=action_record.get("verdict"),
        target=action_record.get("target"),
        transport=action_record.get("transport"),
        signer_key=signer_key_hex,
        chain_seq=action_record.get("chain_seq"),
        chain_prev_hash=action_record.get("chain_prev_hash"),
        timestamp=action_record.get("timestamp"),
    )


def _compute_receipt_hash(receipt: dict[str, Any]) -> str:
    """Chain linkage hash: SHA-256 hex of canonical receipt envelope.

    Matches ``receipt.ReceiptHash`` in ``internal/receipt/chain.go``.
    """
    canonical = canonicalize_receipt(receipt)
    return hashlib.sha256(canonical).hexdigest()


def _verify_chain_list(
    receipts: list[dict[str, Any]],
    public_key_hex: str | None,
) -> ChainResult:
    if not receipts:
        return ChainResult(valid=True, receipt_count=0)

    # v2 chain verification is a v0.3 follow-up. v0.2.0 surfaces v2
    # envelopes via verify_evidence() one at a time. If a chain contains
    # any v2 receipt we fail closed rather than silently treating it as
    # v1, which would falsely fail every v2 chain. Mixed v1/v2 chains
    # are blocked for the same reason: chain-hash bridging across v1
    # and v2 record types is not yet specified.
    for i, receipt in enumerate(receipts):
        if receipt.get("record_type") == "evidence_receipt_v2":
            # Prefer the receipt's declared chain_seq so the failure marker
            # matches the auditor's view of the sequence. Fall back to the
            # list index if the field is absent or not an int (the receipt
            # is being rejected anyway, so further validation is pointless).
            declared = receipt.get("chain_seq")
            broken = declared if isinstance(declared, int) and not isinstance(declared, bool) else i
            return ChainResult(
                valid=False,
                broken_at_seq=broken,
                error=(
                    "v2 chain verification not yet implemented in v0.2.0; "
                    "verify v2 receipts individually with verify_evidence()"
                ),
            )

    # When no key is pinned, lock to the first receipt's signer_key so an
    # attacker can't splice receipts from a second signer into the chain.
    expected_key = public_key_hex or receipts[0].get("signer_key", "")

    prev_hash = _GENESIS_HASH
    for i, receipt in enumerate(receipts):
        ar = receipt.get("action_record") or {}
        seq = ar.get("chain_seq", i)

        result = _verify_receipt_dict(receipt, expected_key)
        if not result.valid:
            return ChainResult(
                valid=False,
                broken_at_seq=seq,
                error=f"seq {seq}: signature: {result.error}",
            )

        if seq != i:
            return ChainResult(
                valid=False,
                broken_at_seq=seq,
                error=f"seq gap: expected {i}, got {seq}",
            )

        actual_prev = ar.get("chain_prev_hash", "")
        if actual_prev != prev_hash:
            return ChainResult(
                valid=False,
                broken_at_seq=seq,
                error=f"seq {seq}: chain_prev_hash mismatch",
            )

        prev_hash = _compute_receipt_hash(receipt)

    first_ar = receipts[0].get("action_record") or {}
    last_ar = receipts[-1].get("action_record") or {}
    return ChainResult(
        valid=True,
        receipt_count=len(receipts),
        final_seq=last_ar.get("chain_seq"),
        root_hash=prev_hash,
        start_time=first_ar.get("timestamp"),
        end_time=last_ar.get("timestamp"),
    )
