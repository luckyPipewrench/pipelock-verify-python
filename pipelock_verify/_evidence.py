"""EvidenceReceipt v2 schema parsing, payload validation, and verification.

Mirrors ``internal/contract/receipt/`` in Pipelock. Strict unknown-field
rejection, recursive data-class validation, JCS canonicalization over typed
structures.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._jcs import JCSError, canonicalize, parse_json_strict
from ._verify import InvalidReceiptError, _is_valid_rfc3339

# Wire format constants matching internal/contract/receipt/receipt.go.
_RECORD_TYPE_EVIDENCE_V2 = "evidence_receipt_v2"
_RECEIPT_VERSION_V2 = 2
_SIGNATURE_PREFIX = "ed25519:"
_SIGNATURE_LEN = 64
_PUBLIC_KEY_LEN = 32

# All 13 payload kinds. Matches the PayloadKind constants in receipt.go.
PAYLOAD_KINDS = frozenset(
    {
        "proxy_decision",
        "contract_ratified",
        "contract_promote_intent",
        "contract_promote_committed",
        "contract_rollback_authorized",
        "contract_rollback_committed",
        "contract_demoted",
        "contract_expired",
        "contract_drift",
        "shadow_delta",
        "opportunity_missing",
        "key_rotation",
        "contract_redaction_request",
    }
)

# Key purpose authority matrix.  Maps payload_kind -> required key_purpose.
# Source: internal/contract/verify.go payloadAuthority.
PAYLOAD_AUTHORITY: dict[str, str] = {
    "proxy_decision": "receipt-signing",
    "contract_ratified": "receipt-signing",
    "contract_promote_intent": "contract-activation-signing",
    "contract_promote_committed": "receipt-signing",
    "contract_rollback_authorized": "contract-activation-signing",
    "contract_rollback_committed": "receipt-signing",
    "contract_demoted": "receipt-signing",
    "contract_expired": "receipt-signing",
    "contract_drift": "receipt-signing",
    "shadow_delta": "receipt-signing",
    "opportunity_missing": "receipt-signing",
    "key_rotation": "contract-activation-signing",
    "contract_redaction_request": "contract-activation-signing",
}

# Top-level envelope fields. Used for unknown-field rejection.
_ENVELOPE_FIELDS = frozenset(
    {
        "record_type",
        "receipt_version",
        "payload_kind",
        "event_id",
        "timestamp",
        "principal",
        "actor",
        "delegation_chain",
        "signature",
        "chain_seq",
        "chain_prev_hash",
        "active_manifest_hash",
        "contract_hash",
        "selector_id",
        "contract_generation",
        "payload",
    }
)

# Signature proof fields. Used for unknown-field rejection.
_SIGNATURE_FIELDS = frozenset(
    {
        "signer_key_id",
        "key_purpose",
        "algorithm",
        "signature",
    }
)

# ---- Payload schemas: maps of field_name -> required ----

_PROXY_DECISION_FIELDS: dict[str, bool] = {
    "action_type": True,
    "target": True,
    "verdict": True,
    "transport": True,
    "policy_sources": True,
    "winning_source": True,
    "rule_id": False,
}

_CONTRACT_RATIFIED_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "ratifier_key_id": True,
    "ratified_rule_ids": True,
    "ratification_decision_per_rule": True,
}

_CONTRACT_PROMOTE_INTENT_FIELDS: dict[str, bool] = {
    "target_manifest_hash": True,
    "target_generation": False,  # uint64 — zero is allowed
    "prior_manifest_hash": True,
    "intent_id": True,
}

_CONTRACT_PROMOTE_COMMITTED_FIELDS: dict[str, bool] = {
    "target_manifest_hash": True,
    "prior_manifest_hash": True,
    "intent_id": True,
    "validation_outcome": True,
    "reject_reason": False,
}

_CONTRACT_ROLLBACK_AUTHORIZED_FIELDS: dict[str, bool] = {
    "rollback_target_hash": True,
    "current_generation": False,  # uint64
    "authorizer_signatures": True,
    "authorization_id": True,
}

_CONTRACT_ROLLBACK_COMMITTED_FIELDS: dict[str, bool] = {
    "rollback_target_hash": True,
    "prior_manifest_hash": True,
    "authorization_id": True,
    "validation_outcome": True,
    "reject_reason": False,
}

_CONTRACT_DEMOTED_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "rule_id": True,
    "demotion_reason": True,
    "prior_state": True,
    "new_state": True,
    "aggregation_window": True,
}

_CONTRACT_EXPIRED_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "rule_id": True,
    "expiration_reason": True,
}

_CONTRACT_DRIFT_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "rule_id": True,
    "drift_kind": True,
    "observation_summary": False,
    "missed_windows": False,
    "opportunity_status": False,
}

_SHADOW_DELTA_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "rule_id": True,
    "original_verdict": True,
    "candidate_verdict": True,
    "aggregation": True,
}

_SHADOW_DELTA_AGGREGATION_FIELDS: dict[str, bool] = {
    "window_start": True,
    "window_end": True,
    "lossless_count": True,
    "delta_sample_count": True,
    "exemplar_ids": True,
}

_OPPORTUNITY_MISSING_FIELDS: dict[str, bool] = {
    "contract_hash": True,
    "rule_id": True,
    "parent_context": True,
    "historical_opportunity_rate": True,
    "current_opportunity_rate": True,
    "window": True,
}

_KEY_ROTATION_FIELDS: dict[str, bool] = {
    "key_id": True,
    "key_purpose": True,
    "old_status": True,
    "new_status": True,
    "roster_hash": True,
    "authorization_id": True,
}

_CONTRACT_REDACTION_REQUEST_FIELDS: dict[str, bool] = {
    "target_contract_hash": True,
    "request_kind": True,
    "reason_class": True,
    "authorization_id": True,
    "tombstone_hash": True,
}

_VALID_VALIDATION_OUTCOMES = frozenset({"accepted", "rejected"})
_VALID_REQUEST_KINDS = frozenset({"withdraw_public_proof", "local_erasure_tombstone"})


@dataclass
class EvidenceVerifyResult:
    """Outcome of verifying a single EvidenceReceipt v2.

    ``valid`` is the only field guaranteed to be set. Descriptive fields
    are populated on success (and may be on some failures) for diagnostic
    output. ``error`` holds a short reason string on failure.
    """

    valid: bool
    error: str | None = None
    event_id: str | None = None
    record_type: str | None = None
    payload_kind: str | None = None
    signer_key_id: str | None = None
    key_purpose: str | None = None
    chain_seq: int | None = None
    chain_prev_hash: str | None = None
    timestamp: str | None = None


def verify_evidence(
    receipt: dict[str, Any],
    public_key_hex: str | None = None,
    expected_signer_key_id: str | None = None,
    expected_key_purpose: str | None = None,
) -> EvidenceVerifyResult:
    """Verify a single EvidenceReceipt v2 envelope.

    Args:
        receipt: Pre-parsed receipt dict.
        public_key_hex: Optional trust anchor. When supplied, the signer's
            public key (resolved from the signer_key_id) must match.
            For standalone verification, pass the hex-encoded 32-byte Ed25519
            public key directly.
        expected_signer_key_id: If set, receipt's signer_key_id must match.
        expected_key_purpose: If set, receipt's key_purpose must match.
            When not set, the authority matrix is still enforced.

    Returns:
        An :class:`EvidenceVerifyResult`.
    """
    # Envelope structural checks.
    record_type = receipt.get("record_type")
    if record_type != _RECORD_TYPE_EVIDENCE_V2:
        return EvidenceVerifyResult(
            valid=False,
            error=f"unsupported record_type {record_type!r} (expected {_RECORD_TYPE_EVIDENCE_V2!r})",
        )

    version = receipt.get("receipt_version")
    if version != _RECEIPT_VERSION_V2:
        return EvidenceVerifyResult(
            valid=False,
            error=f"unsupported receipt_version {version} (expected {_RECEIPT_VERSION_V2})",
        )

    # Unknown field rejection at envelope level.
    unknown_envelope = set(receipt.keys()) - _ENVELOPE_FIELDS
    if unknown_envelope:
        return EvidenceVerifyResult(
            valid=False,
            error=f"unknown envelope fields: {sorted(unknown_envelope)}",
        )

    event_id = receipt.get("event_id", "")
    if not event_id:
        return EvidenceVerifyResult(valid=False, error="event_id is required")

    timestamp = receipt.get("timestamp", "")
    if not timestamp:
        return EvidenceVerifyResult(valid=False, error="timestamp is required")
    if not _is_valid_rfc3339(timestamp):
        return EvidenceVerifyResult(
            valid=False,
            error=f"invalid RFC 3339 timestamp: {timestamp!r}",
        )

    payload_kind = receipt.get("payload_kind", "")
    if payload_kind not in PAYLOAD_KINDS:
        return EvidenceVerifyResult(
            valid=False,
            error=f"unknown payload_kind: {payload_kind!r}",
        )

    # Signature proof structural checks.
    sig_proof = receipt.get("signature")
    if not isinstance(sig_proof, dict):
        return EvidenceVerifyResult(valid=False, error="missing or invalid signature proof")

    unknown_sig = set(sig_proof.keys()) - _SIGNATURE_FIELDS
    if unknown_sig:
        return EvidenceVerifyResult(
            valid=False,
            error=f"unknown signature fields: {sorted(unknown_sig)}",
        )

    signer_key_id = sig_proof.get("signer_key_id", "")
    if not signer_key_id:
        return EvidenceVerifyResult(valid=False, error="signature.signer_key_id is required")

    key_purpose = sig_proof.get("key_purpose", "")
    if not key_purpose:
        return EvidenceVerifyResult(valid=False, error="signature.key_purpose is required")

    # Authority matrix check.
    required_purpose = PAYLOAD_AUTHORITY.get(payload_kind)
    if required_purpose and key_purpose != required_purpose:
        return EvidenceVerifyResult(
            valid=False,
            error=(
                f"key_purpose mismatch: payload_kind={payload_kind!r} "
                f"requires {required_purpose!r}, got {key_purpose!r}"
            ),
        )

    # Caller-supplied purpose check.
    if expected_key_purpose and key_purpose != expected_key_purpose:
        return EvidenceVerifyResult(
            valid=False,
            error=f"key_purpose {key_purpose!r} does not match expected {expected_key_purpose!r}",
        )

    algorithm = sig_proof.get("algorithm", "")
    if algorithm != "ed25519":
        return EvidenceVerifyResult(
            valid=False,
            error=f"unsupported signature algorithm: {algorithm!r}",
        )

    sig_value = sig_proof.get("signature", "")
    if not isinstance(sig_value, str) or not sig_value.startswith(_SIGNATURE_PREFIX):
        return EvidenceVerifyResult(
            valid=False,
            error=f"invalid signature format: missing {_SIGNATURE_PREFIX} prefix",
        )

    sig_hex = sig_value[len(_SIGNATURE_PREFIX) :]
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
        return EvidenceVerifyResult(valid=False, error=f"decoding signature: {exc}")
    if len(sig_bytes) != _SIGNATURE_LEN:
        return EvidenceVerifyResult(
            valid=False,
            error=f"invalid signature length: got {len(sig_bytes)}, want {_SIGNATURE_LEN}",
        )

    # Caller-supplied signer_key_id check.
    if expected_signer_key_id and signer_key_id != expected_signer_key_id:
        return EvidenceVerifyResult(
            valid=False,
            error=(
                f"signer_key_id {signer_key_id!r} does not match "
                f"expected {expected_signer_key_id!r}"
            ),
        )

    # Payload validation (strict unknown-field rejection).
    payload = receipt.get("payload")
    err = _validate_payload(payload_kind, payload)
    if err:
        return EvidenceVerifyResult(valid=False, error=err)

    # Fail closed when no verification key is provided. v2 envelopes do
    # not embed a signer public key, so callers MUST supply one. Accepting
    # a structurally-valid receipt without verifying its signature would
    # let an attacker pass any envelope through verify_evidence().
    if not public_key_hex:
        return EvidenceVerifyResult(
            valid=False,
            error="public_key_hex is required to verify EvidenceReceipt v2 signatures",
        )

    try:
        pub_key_bytes = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        return EvidenceVerifyResult(valid=False, error=f"decoding public_key: {exc}")
    if len(pub_key_bytes) != _PUBLIC_KEY_LEN:
        return EvidenceVerifyResult(
            valid=False,
            error=f"invalid public_key length: got {len(pub_key_bytes)}, want {_PUBLIC_KEY_LEN}",
        )

    try:
        preimage = _signable_preimage(receipt)
    except (JCSError, InvalidReceiptError) as exc:
        return EvidenceVerifyResult(valid=False, error=f"computing preimage: {exc}")

    try:
        Ed25519PublicKey.from_public_bytes(pub_key_bytes).verify(sig_bytes, preimage)
    except InvalidSignature:
        return EvidenceVerifyResult(valid=False, error="signature verification failed")

    return EvidenceVerifyResult(
        valid=True,
        event_id=event_id,
        record_type=record_type,
        payload_kind=payload_kind,
        signer_key_id=signer_key_id,
        key_purpose=key_purpose,
        chain_seq=receipt.get("chain_seq"),
        chain_prev_hash=receipt.get("chain_prev_hash"),
        timestamp=timestamp,
    )


def _signable_preimage(receipt: dict[str, Any]) -> bytes:
    """Compute the JCS-canonical signable preimage for an EvidenceReceipt v2.

    Recipe: clone receipt, zero out signature, JCS-canonicalize the result.
    The signature object is replaced with a zeroed-out structure (all fields
    present but empty/default) to match Go's behavior where the zero-value
    struct is marshalled.
    """
    clone = dict(receipt)
    clone["signature"] = {
        "signer_key_id": "",
        "key_purpose": "",
        "algorithm": "",
        "signature": "",
    }
    # Re-parse through strict parser to get integer-preserving tree,
    # then canonicalize.
    raw = json.dumps(clone, separators=(",", ":"), ensure_ascii=False)
    tree = parse_json_strict(raw)
    return canonicalize(tree)


def evidence_receipt_hash(receipt: dict[str, Any]) -> str:
    """Compute the SHA-256 hex digest of the JCS-canonical full receipt.

    Used for chain linkage in v2 receipt chains.
    """
    raw = json.dumps(receipt, separators=(",", ":"), ensure_ascii=False)
    tree = parse_json_strict(raw)
    canonical = canonicalize(tree)
    return hashlib.sha256(canonical).hexdigest()


# ---- Payload validation ----


def _validate_payload(payload_kind: str, payload: Any) -> str | None:
    """Validate payload structure for a given payload_kind.

    Returns an error string on failure, None on success.
    """
    if payload is None:
        return "payload is required"
    if not isinstance(payload, dict):
        return "payload must be a JSON object"

    validator = _PAYLOAD_VALIDATORS.get(payload_kind)
    if validator is None:
        return f"no validator for payload_kind {payload_kind!r}"

    return validator(payload)


# Fields documented as integer / uint counts in the Go reference. A string
# carrying "5" must NOT pass validation because the Go side parses these as
# typed integers and the JCS preimage byte-shape differs (`5` vs `"5"`).
# Cross-implementation drift bug surface: keep this list in sync with
# internal/contract/receipt/payload.go field types in pipelock.
_INT_FIELDS: frozenset[str] = frozenset(
    {
        "current_generation",
        "target_generation",
        "lossless_count",
        "delta_sample_count",
    }
)


def _check_fields(
    payload: dict[str, Any],
    schema: dict[str, bool],
    context: str = "",
) -> str | None:
    """Check for unknown fields, required fields, and basic field types.

    schema maps field_name -> required. Unknown fields are rejected.
    Required string fields must be non-empty. Required list/dict fields
    must be non-empty. Fields named in ``_INT_FIELDS`` must arrive as
    Python ``int`` (not str), because the Go reference emits them as
    typed integers and the JCS preimage byte-shape differs.

    NOTE: for v0.2.0 the type guard is limited to integer-shaped count
    fields. Full per-field type schemas (string vs list-of-string vs
    nested object shape) are tracked as a v0.3 follow-up.
    """
    known = set(schema.keys())
    unknown = set(payload.keys()) - known
    if unknown:
        prefix = f"{context}: " if context else ""
        return f"{prefix}unknown payload fields: {sorted(unknown)}"

    for field, required in schema.items():
        value = payload.get(field)
        if field in _INT_FIELDS and value is not None and not isinstance(value, int):
            # Reject bool too: bool is a subclass of int in Python so
            # isinstance(True, int) is True, but bool in a count slot is
            # a typing bug. None is allowed — handled by required-check.
            if isinstance(value, bool) or not isinstance(value, int):
                return f"payload field {field!r} must be an integer, got {type(value).__name__}"
        if not required:
            continue
        if value is None:
            return f"payload missing required field: {field}"
        if isinstance(value, str) and value == "":
            return f"payload missing required field: {field}"
        if isinstance(value, (list, dict)) and len(value) == 0:
            return f"payload missing required field: {field}"

    return None


def _validate_proxy_decision(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _PROXY_DECISION_FIELDS)
    if err:
        return err
    ps = payload.get("policy_sources")
    if not isinstance(ps, list):
        return "payload policy_sources must be a list"
    return None


def _validate_contract_ratified(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _CONTRACT_RATIFIED_FIELDS)
    if err:
        return err
    rdpr = payload.get("ratification_decision_per_rule")
    if not isinstance(rdpr, dict):
        return "payload ratification_decision_per_rule must be an object"
    return None


def _validate_contract_promote_intent(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _CONTRACT_PROMOTE_INTENT_FIELDS)


def _validate_contract_promote_committed(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _CONTRACT_PROMOTE_COMMITTED_FIELDS)
    if err:
        return err
    outcome = payload.get("validation_outcome", "")
    if outcome not in _VALID_VALIDATION_OUTCOMES:
        return f"payload validation_outcome must be 'accepted' or 'rejected', got {outcome!r}"
    if outcome == "rejected":
        reason = payload.get("reject_reason", "")
        if not reason:
            return "payload reject_reason is required when validation_outcome is 'rejected'"
    return None


def _validate_contract_rollback_authorized(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _CONTRACT_ROLLBACK_AUTHORIZED_FIELDS)
    if err:
        return err
    sigs = payload.get("authorizer_signatures")
    if not isinstance(sigs, list):
        return "payload authorizer_signatures must be a list"
    return None


def _validate_contract_rollback_committed(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _CONTRACT_ROLLBACK_COMMITTED_FIELDS)
    if err:
        return err
    outcome = payload.get("validation_outcome", "")
    if outcome not in _VALID_VALIDATION_OUTCOMES:
        return f"payload validation_outcome must be 'accepted' or 'rejected', got {outcome!r}"
    if outcome == "rejected":
        reason = payload.get("reject_reason", "")
        if not reason:
            return "payload reject_reason is required when validation_outcome is 'rejected'"
    return None


def _validate_contract_demoted(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _CONTRACT_DEMOTED_FIELDS)


def _validate_contract_expired(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _CONTRACT_EXPIRED_FIELDS)


def _validate_contract_drift(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _CONTRACT_DRIFT_FIELDS)


def _validate_shadow_delta(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _SHADOW_DELTA_FIELDS)
    if err:
        return err
    agg = payload.get("aggregation")
    if not isinstance(agg, dict):
        return "payload aggregation must be an object"
    return _validate_shadow_delta_aggregation(agg)


def _validate_shadow_delta_aggregation(agg: dict[str, Any]) -> str | None:
    err = _check_fields(agg, _SHADOW_DELTA_AGGREGATION_FIELDS, context="aggregation")
    if err:
        return err
    # Validate window timestamps.
    ws = agg.get("window_start", "")
    we = agg.get("window_end", "")
    if not _is_valid_rfc3339(ws):
        return f"aggregation.window_start is not valid RFC 3339: {ws!r}"
    if not _is_valid_rfc3339(we):
        return f"aggregation.window_end is not valid RFC 3339: {we!r}"
    return None


def _validate_opportunity_missing(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _OPPORTUNITY_MISSING_FIELDS)


def _validate_key_rotation(payload: dict[str, Any]) -> str | None:
    return _check_fields(payload, _KEY_ROTATION_FIELDS)


def _validate_contract_redaction_request(payload: dict[str, Any]) -> str | None:
    err = _check_fields(payload, _CONTRACT_REDACTION_REQUEST_FIELDS)
    if err:
        return err
    rk = payload.get("request_kind", "")
    if rk not in _VALID_REQUEST_KINDS:
        return (
            f"payload request_kind must be 'withdraw_public_proof' or "
            f"'local_erasure_tombstone', got {rk!r}"
        )
    return None


_PAYLOAD_VALIDATORS: dict[str, Any] = {
    "proxy_decision": _validate_proxy_decision,
    "contract_ratified": _validate_contract_ratified,
    "contract_promote_intent": _validate_contract_promote_intent,
    "contract_promote_committed": _validate_contract_promote_committed,
    "contract_rollback_authorized": _validate_contract_rollback_authorized,
    "contract_rollback_committed": _validate_contract_rollback_committed,
    "contract_demoted": _validate_contract_demoted,
    "contract_expired": _validate_contract_expired,
    "contract_drift": _validate_contract_drift,
    "shadow_delta": _validate_shadow_delta,
    "opportunity_missing": _validate_opportunity_missing,
    "key_rotation": _validate_key_rotation,
    "contract_redaction_request": _validate_contract_redaction_request,
}
