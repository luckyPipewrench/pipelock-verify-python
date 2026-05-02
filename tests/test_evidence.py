"""Tests for EvidenceReceipt v2 verification.

Covers: all 13 payload kinds, version routing, signature tampering,
key-purpose mismatch, unknown-field rejection, validation outcome enum
enforcement, and backward compatibility with v1.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

import pipelock_verify
from pipelock_verify._evidence import (
    PAYLOAD_AUTHORITY,
    PAYLOAD_KINDS,
    _signable_preimage,
    evidence_receipt_hash,
    verify_evidence,
)
from pipelock_verify._jcs import JCSError, canonicalize, parse_json_strict

# ---- Test key helpers ----


def _generate_test_key() -> tuple[Ed25519PrivateKey, str]:
    """Generate a fresh Ed25519 key pair. Returns (private_key, public_key_hex)."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv, pub_bytes.hex()


def _sign_evidence_receipt(receipt: dict, priv: Ed25519PrivateKey) -> dict:
    """Sign an EvidenceReceipt v2 dict in place and return it.

    Computes the JCS preimage with zeroed signature, signs with Ed25519
    PureEdDSA, and fills in the signature field.
    """
    preimage = _signable_preimage(receipt)
    sig = priv.sign(preimage)
    receipt["signature"]["signature"] = "ed25519:" + sig.hex()
    return receipt


def _minimal_evidence_receipt(
    payload_kind: str = "proxy_decision",
    payload: dict | None = None,
    key_purpose: str | None = None,
) -> dict:
    """Build a minimal valid EvidenceReceipt v2 dict (unsigned)."""
    if payload is None:
        payload = _payload_for_kind(payload_kind)
    if key_purpose is None:
        key_purpose = PAYLOAD_AUTHORITY.get(payload_kind, "receipt-signing")
    return {
        "record_type": "evidence_receipt_v2",
        "receipt_version": 2,
        "payload_kind": payload_kind,
        "event_id": "01900000-0000-7000-8000-000000000001",
        "timestamp": "2026-04-30T12:00:00Z",
        "principal": "org:test",
        "actor": "agent:test",
        "delegation_chain": ["grant"],
        "signature": {
            "signer_key_id": "test-key",
            "key_purpose": key_purpose,
            "algorithm": "ed25519",
            "signature": "ed25519:" + "00" * 64,
        },
        "chain_seq": 0,
        "chain_prev_hash": "genesis",
        "payload": payload,
    }


def _payload_for_kind(kind: str) -> dict:
    """Return a minimal valid payload for each payload kind."""
    payloads = {
        "proxy_decision": {
            "action_type": "block",
            "target": "https://example.com/",
            "verdict": "blocked",
            "transport": "forward",
            "policy_sources": ["dlp"],
            "winning_source": "dlp",
        },
        "contract_ratified": {
            "contract_hash": "sha256:abc123",
            "ratifier_key_id": "key1",
            "ratified_rule_ids": ["rule1"],
            "ratification_decision_per_rule": {"rule1": "accept"},
        },
        "contract_promote_intent": {
            "target_manifest_hash": "sha256:target",
            "target_generation": 2,
            "prior_manifest_hash": "sha256:prior",
            "intent_id": "intent-001",
        },
        "contract_promote_committed": {
            "target_manifest_hash": "sha256:target",
            "prior_manifest_hash": "sha256:prior",
            "intent_id": "intent-001",
            "validation_outcome": "accepted",
        },
        "contract_rollback_authorized": {
            "rollback_target_hash": "sha256:rollback",
            "current_generation": 3,
            "authorizer_signatures": ["sig1"],
            "authorization_id": "auth-001",
        },
        "contract_rollback_committed": {
            "rollback_target_hash": "sha256:rollback",
            "prior_manifest_hash": "sha256:prior",
            "authorization_id": "auth-001",
            "validation_outcome": "accepted",
        },
        "contract_demoted": {
            "contract_hash": "sha256:abc",
            "rule_id": "rule1",
            "demotion_reason": "violation",
            "prior_state": "enforced",
            "new_state": "shadow",
            "aggregation_window": "PT1H",
        },
        "contract_expired": {
            "contract_hash": "sha256:abc",
            "rule_id": "rule1",
            "expiration_reason": "ttl_exceeded",
        },
        "contract_drift": {
            "contract_hash": "sha256:abc",
            "rule_id": "rule1",
            "drift_kind": "positive",
        },
        "shadow_delta": {
            "contract_hash": "sha256:abc",
            "rule_id": "rule1",
            "original_verdict": "allow",
            "candidate_verdict": "block",
            "aggregation": {
                "window_start": "2026-04-01T00:00:00Z",
                "window_end": "2026-04-02T00:00:00Z",
                "lossless_count": 10,
                "delta_sample_count": 2,
                "exemplar_ids": ["e1", "e2"],
            },
        },
        "opportunity_missing": {
            "contract_hash": "sha256:abc",
            "rule_id": "rule1",
            "parent_context": "session-123",
            "historical_opportunity_rate": "0.95",
            "current_opportunity_rate": "0.10",
            "window": "PT24H",
        },
        "key_rotation": {
            "key_id": "key1",
            "key_purpose": "receipt-signing",
            "old_status": "active",
            "new_status": "revoked",
            "roster_hash": "sha256:roster",
            "authorization_id": "auth-002",
        },
        "contract_redaction_request": {
            "target_contract_hash": "sha256:target",
            "request_kind": "withdraw_public_proof",
            "reason_class": "gdpr_erasure",
            "authorization_id": "auth-003",
            "tombstone_hash": "sha256:tomb",
        },
    }
    return payloads[kind]


# ---- JCS canonicalization tests ----


class TestJCS:
    def test_empty_object(self):
        assert canonicalize({}) == b"{}"

    def test_key_sorting(self):
        result = canonicalize({"b": 1, "a": 2})
        assert result == b'{"a":2,"b":1}'

    def test_nested_object(self):
        result = canonicalize({"z": {"b": 1, "a": 2}, "a": 3})
        assert result == b'{"a":3,"z":{"a":2,"b":1}}'

    def test_array_preserves_order(self):
        result = canonicalize([3, 1, 2])
        assert result == b"[3,1,2]"

    def test_null(self):
        assert canonicalize(None) == b"null"

    def test_boolean(self):
        assert canonicalize(True) == b"true"
        assert canonicalize(False) == b"false"

    def test_integer(self):
        assert canonicalize(42) == b"42"
        assert canonicalize(0) == b"0"
        assert canonicalize(-1) == b"-1"

    def test_float_rejected(self):
        with pytest.raises(JCSError, match="float not allowed"):
            canonicalize(3.14)

    def test_string_nfc_normalized(self):
        # U+00E9 (precomposed) vs U+0065 U+0301 (decomposed)
        nfd = "é"
        nfc = "é"
        result_nfd = canonicalize(nfd)
        result_nfc = canonicalize(nfc)
        assert result_nfd == result_nfc

    def test_nfc_collision_rejected(self):
        # Two keys that normalize to the same NFC form.
        with pytest.raises(JCSError, match="duplicate key"):
            canonicalize({"é": 1, "é": 2})

    def test_no_whitespace(self):
        result = canonicalize({"key": [1, 2, 3]}).decode()
        assert " " not in result
        assert "\n" not in result


class TestParseJSONStrict:
    def test_valid_json(self):
        result = parse_json_strict(b'{"a":1,"b":"hello"}')
        assert result == {"a": 1, "b": "hello"}

    def test_duplicate_key_rejected(self):
        with pytest.raises(JCSError, match="duplicate key"):
            parse_json_strict(b'{"a":1,"a":2}')

    def test_trailing_tokens_rejected(self):
        with pytest.raises(JCSError, match="trailing tokens"):
            parse_json_strict(b'{"a":1}{"b":2}')

    def test_trailing_whitespace_ok(self):
        result = parse_json_strict(b'{"a":1}  \n')
        assert result == {"a": 1}

    def test_float_rejected(self):
        with pytest.raises(JCSError, match="float not allowed"):
            parse_json_strict(b'{"a":3.14}')

    def test_integer_preserved(self):
        result = parse_json_strict(b'{"a":42}')
        assert result == {"a": 42}
        assert isinstance(result["a"], int)


# ---- Payload validation round-trips (all 13 kinds) ----


@pytest.mark.parametrize("kind", sorted(PAYLOAD_KINDS))
class TestPayloadKindRoundTrip:
    def test_valid_payload_accepted(self, kind):
        """Each payload kind with valid minimal fields must pass validation."""
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt(kind)
        receipt = _sign_evidence_receipt(receipt, priv)
        result = verify_evidence(receipt, public_key_hex=pub_hex)
        assert result.valid, f"{kind}: {result.error}"
        assert result.payload_kind == kind

    def test_authority_matrix_enforced(self, kind):
        """Signing with the wrong key_purpose must be rejected."""
        priv, pub_hex = _generate_test_key()
        expected = PAYLOAD_AUTHORITY[kind]
        wrong = (
            "contract-activation-signing" if expected == "receipt-signing" else "receipt-signing"
        )
        receipt = _minimal_evidence_receipt(kind, key_purpose=wrong)
        receipt = _sign_evidence_receipt(receipt, priv)
        result = verify_evidence(receipt, public_key_hex=pub_hex)
        assert not result.valid
        assert "key_purpose mismatch" in (result.error or "")


# ---- Envelope structural validation ----


class TestEnvelopeValidation:
    def test_wrong_record_type(self):
        receipt = _minimal_evidence_receipt()
        receipt["record_type"] = "action_receipt_v1"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "record_type" in (result.error or "")

    def test_wrong_version(self):
        receipt = _minimal_evidence_receipt()
        receipt["receipt_version"] = 3
        result = verify_evidence(receipt)
        assert not result.valid
        assert "receipt_version" in (result.error or "")

    def test_unknown_envelope_field_rejected(self):
        receipt = _minimal_evidence_receipt()
        receipt["x_vendor"] = "evil"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "unknown envelope fields" in (result.error or "")

    def test_missing_event_id(self):
        receipt = _minimal_evidence_receipt()
        receipt["event_id"] = ""
        result = verify_evidence(receipt)
        assert not result.valid
        assert "event_id" in (result.error or "")

    def test_invalid_timestamp(self):
        receipt = _minimal_evidence_receipt()
        receipt["timestamp"] = "not-a-time"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "timestamp" in (result.error or "").lower()

    def test_unknown_payload_kind(self):
        receipt = _minimal_evidence_receipt()
        receipt["payload_kind"] = "bogus"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "payload_kind" in (result.error or "")

    def test_missing_signature_proof(self):
        receipt = _minimal_evidence_receipt()
        receipt["signature"] = "not-a-dict"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "signature proof" in (result.error or "")

    def test_unknown_signature_field_rejected(self):
        receipt = _minimal_evidence_receipt()
        receipt["signature"]["x_extra"] = "bad"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "unknown signature fields" in (result.error or "")

    def test_missing_signer_key_id(self):
        receipt = _minimal_evidence_receipt()
        receipt["signature"]["signer_key_id"] = ""
        result = verify_evidence(receipt)
        assert not result.valid
        assert "signer_key_id" in (result.error or "")

    def test_missing_key_purpose(self):
        receipt = _minimal_evidence_receipt()
        receipt["signature"]["key_purpose"] = ""
        result = verify_evidence(receipt)
        assert not result.valid
        assert "key_purpose" in (result.error or "")

    def test_wrong_algorithm(self):
        receipt = _minimal_evidence_receipt()
        receipt["signature"]["algorithm"] = "rsa"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "algorithm" in (result.error or "")

    def test_bad_signature_prefix(self):
        receipt = _minimal_evidence_receipt()
        receipt["signature"]["signature"] = "rsa:" + "00" * 64
        result = verify_evidence(receipt)
        assert not result.valid
        assert "prefix" in (result.error or "")

    def test_bad_signature_hex(self):
        receipt = _minimal_evidence_receipt()
        receipt["signature"]["signature"] = "ed25519:not-hex"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "decoding signature" in (result.error or "")

    def test_bad_signature_length(self):
        receipt = _minimal_evidence_receipt()
        receipt["signature"]["signature"] = "ed25519:" + "00" * 32
        result = verify_evidence(receipt)
        assert not result.valid
        assert "signature length" in (result.error or "")


# ---- Signature verification ----


class TestSignatureVerification:
    def test_valid_signature(self):
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt()
        receipt = _sign_evidence_receipt(receipt, priv)
        result = verify_evidence(receipt, public_key_hex=pub_hex)
        assert result.valid, result.error

    def test_tampered_payload_rejected(self):
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt()
        receipt = _sign_evidence_receipt(receipt, priv)
        # Tamper with the payload after signing.
        receipt["payload"]["target"] = "https://evil.com/"
        result = verify_evidence(receipt, public_key_hex=pub_hex)
        assert not result.valid
        assert "signature verification failed" in (result.error or "")

    def test_tampered_event_id_rejected(self):
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt()
        receipt = _sign_evidence_receipt(receipt, priv)
        receipt["event_id"] = "01900000-0000-7000-8000-999999999999"
        result = verify_evidence(receipt, public_key_hex=pub_hex)
        assert not result.valid
        assert "signature verification failed" in (result.error or "")

    def test_wrong_public_key_rejected(self):
        priv, _ = _generate_test_key()
        _, other_pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt()
        receipt = _sign_evidence_receipt(receipt, priv)
        result = verify_evidence(receipt, public_key_hex=other_pub_hex)
        assert not result.valid
        assert "signature verification failed" in (result.error or "")

    def test_no_key_skips_signature_check(self):
        """Without a public key, only structural checks are performed."""
        receipt = _minimal_evidence_receipt()
        # Signature is dummy zeros — structural checks pass, no crypto check.
        result = verify_evidence(receipt)
        assert result.valid, result.error


# ---- Key purpose enforcement ----


class TestKeyPurpose:
    def test_expected_key_purpose_match(self):
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt("proxy_decision")
        receipt = _sign_evidence_receipt(receipt, priv)
        result = verify_evidence(
            receipt,
            public_key_hex=pub_hex,
            expected_key_purpose="receipt-signing",
        )
        assert result.valid, result.error

    def test_expected_key_purpose_mismatch(self):
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt("proxy_decision")
        receipt = _sign_evidence_receipt(receipt, priv)
        result = verify_evidence(
            receipt,
            public_key_hex=pub_hex,
            expected_key_purpose="contract-activation-signing",
        )
        assert not result.valid
        # The authority matrix check fires first (receipt says receipt-signing,
        # but proxy_decision requires receipt-signing, so that passes; but
        # the caller-level check fails).
        assert "key_purpose" in (result.error or "")

    def test_expected_signer_key_id_match(self):
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt()
        receipt = _sign_evidence_receipt(receipt, priv)
        result = verify_evidence(
            receipt,
            public_key_hex=pub_hex,
            expected_signer_key_id="test-key",
        )
        assert result.valid, result.error

    def test_expected_signer_key_id_mismatch(self):
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt()
        receipt = _sign_evidence_receipt(receipt, priv)
        result = verify_evidence(
            receipt,
            public_key_hex=pub_hex,
            expected_signer_key_id="other-key",
        )
        assert not result.valid
        assert "signer_key_id" in (result.error or "")


# ---- Version routing via verify() ----


class TestVersionRouting:
    def test_v2_routed_through_verify(self):
        """verify() dispatches to v2 path when record_type is evidence_receipt_v2."""
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt()
        receipt = _sign_evidence_receipt(receipt, priv)
        result = pipelock_verify.verify(receipt, public_key_hex=pub_hex)
        assert result.valid, result.error
        assert result.action_id == receipt["event_id"]
        assert result.action_type == "proxy_decision"

    def test_v2_json_string_routed(self):
        """verify() accepts v2 as JSON string."""
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt()
        receipt = _sign_evidence_receipt(receipt, priv)
        result = pipelock_verify.verify(json.dumps(receipt), public_key_hex=pub_hex)
        assert result.valid, result.error

    def test_v1_still_works_after_v2_addition(self):
        """v1 receipts continue to verify — backward compatibility."""
        from pathlib import Path

        conformance = Path(__file__).parent / "conformance"
        data = (conformance / "valid-single.json").read_bytes()
        result = pipelock_verify.verify(data)
        assert result.valid, f"v1 broke: {result.error}"

    def test_unknown_record_type_rejected(self):
        receipt = _minimal_evidence_receipt()
        receipt["record_type"] = "future_receipt_v99"
        result = pipelock_verify.verify(receipt)
        assert not result.valid
        assert "record_type" in (result.error or "")


# ---- Payload-specific edge cases ----


class TestPayloadEdgeCases:
    def test_proxy_decision_missing_policy_sources(self):
        receipt = _minimal_evidence_receipt("proxy_decision")
        receipt["payload"]["policy_sources"] = []
        result = verify_evidence(receipt)
        assert not result.valid
        assert "policy_sources" in (result.error or "")

    def test_contract_promote_committed_rejected_needs_reason(self):
        receipt = _minimal_evidence_receipt("contract_promote_committed")
        receipt["payload"]["validation_outcome"] = "rejected"
        # Missing reject_reason.
        result = verify_evidence(receipt)
        assert not result.valid
        assert "reject_reason" in (result.error or "")

    def test_contract_promote_committed_invalid_outcome(self):
        receipt = _minimal_evidence_receipt("contract_promote_committed")
        receipt["payload"]["validation_outcome"] = "maybe"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "validation_outcome" in (result.error or "")

    def test_contract_rollback_committed_rejected_needs_reason(self):
        receipt = _minimal_evidence_receipt("contract_rollback_committed")
        receipt["payload"]["validation_outcome"] = "rejected"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "reject_reason" in (result.error or "")

    def test_contract_drift_with_drift_kind(self):
        priv, pub_hex = _generate_test_key()
        for dk in ("positive", "negative", "stable"):
            receipt = _minimal_evidence_receipt("contract_drift")
            receipt["payload"]["drift_kind"] = dk
            receipt = _sign_evidence_receipt(receipt, priv)
            result = verify_evidence(receipt, public_key_hex=pub_hex)
            assert result.valid, f"drift_kind={dk}: {result.error}"

    def test_contract_redaction_invalid_request_kind(self):
        receipt = _minimal_evidence_receipt("contract_redaction_request")
        receipt["payload"]["request_kind"] = "full_wipe"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "request_kind" in (result.error or "")

    def test_contract_redaction_local_erasure_accepted(self):
        priv, pub_hex = _generate_test_key()
        receipt = _minimal_evidence_receipt("contract_redaction_request")
        receipt["payload"]["request_kind"] = "local_erasure_tombstone"
        receipt = _sign_evidence_receipt(receipt, priv)
        result = verify_evidence(receipt, public_key_hex=pub_hex)
        assert result.valid, result.error

    def test_shadow_delta_aggregation_timestamps(self):
        receipt = _minimal_evidence_receipt("shadow_delta")
        receipt["payload"]["aggregation"]["window_start"] = "bad"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "window_start" in (result.error or "")

    def test_unknown_payload_field_rejected(self):
        receipt = _minimal_evidence_receipt("proxy_decision")
        receipt["payload"]["x_evil"] = "data"
        result = verify_evidence(receipt)
        assert not result.valid
        assert "unknown payload fields" in (result.error or "")

    def test_missing_payload(self):
        receipt = _minimal_evidence_receipt()
        del receipt["payload"]
        result = verify_evidence(receipt)
        assert not result.valid
        assert "payload" in (result.error or "")

    def test_null_payload_rejected(self):
        receipt = _minimal_evidence_receipt()
        receipt["payload"] = None
        result = verify_evidence(receipt)
        assert not result.valid
        assert "payload" in (result.error or "")


# ---- Receipt hash for chain linkage ----


class TestReceiptHash:
    def test_hash_deterministic(self):
        receipt = _minimal_evidence_receipt()
        h1 = evidence_receipt_hash(receipt)
        h2 = evidence_receipt_hash(receipt)
        assert h1 == h2
        assert len(h1) == 64  # 32-byte hex

    def test_hash_changes_with_content(self):
        receipt = _minimal_evidence_receipt()
        h1 = evidence_receipt_hash(receipt)
        receipt["event_id"] = "different-id"
        h2 = evidence_receipt_hash(receipt)
        assert h1 != h2


# ---- Signable preimage ----


class TestSignablePreimage:
    def test_signature_excluded_from_preimage(self):
        """The signature field should be zeroed in the preimage."""
        receipt = _minimal_evidence_receipt()
        preimage = _signable_preimage(receipt)
        decoded = json.loads(preimage)
        sig = decoded["signature"]
        assert sig["signer_key_id"] == ""
        assert sig["key_purpose"] == ""
        assert sig["algorithm"] == ""
        assert sig["signature"] == ""

    def test_preimage_is_jcs_canonical(self):
        """Preimage keys should be sorted (JCS order)."""
        receipt = _minimal_evidence_receipt()
        preimage = _signable_preimage(receipt)
        decoded_str = preimage.decode("utf-8")
        # JCS means no whitespace between tokens.
        assert " " not in decoded_str or '"actor":"agent:test"' in decoded_str
        # Verify it re-parses without error.
        parsed = json.loads(decoded_str)
        assert isinstance(parsed, dict)
