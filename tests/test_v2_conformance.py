# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Cross-implementation conformance tests for EvidenceReceipt v2.

The fixtures in tests/conformance/valid-evidence-*.json are emitted by
the Go reference implementation (pipelock/internal/contract/receipt)
under deterministic test signing keys. Each fixture round-trips through
the Python verifier; if the Go side ever changes its byte output for
a given input, the Python verifier MUST detect the change as a
signature failure (because the JCS preimage no longer matches), and
this test fails before v2.4 ships.

Adding a new payload kind: emit it from the Go side via
internal/contract/receipt/golden_vectors_test.go (run with
UPDATE_GOLDEN=1) into testdata/golden/, copy into this repo's
conformance dir, and parametrise the new fixture name below.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipelock_verify import verify_evidence

CONFORMANCE_DIR = Path(__file__).parent / "conformance"

# The Go reference signs every fixture with the RFC 8032 section 7.1
# test-1 private seed (hex 9d61...7f60). The corresponding public key
# is below. v2-test-keys.json carries it, but pulling it inline here
# keeps the test self-contained against accidental fixture moves.
RFC8032_TEST1_PUBLIC_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

# Fixtures copied from pipelock/internal/contract/testdata/golden/.
# Each entry: (fixture-filename, expected-payload-kind).
V2_FIXTURES = [
    ("valid-evidence-proxy-decision.json", "proxy_decision"),
    ("valid-evidence-promote-committed.json", "contract_promote_committed"),
    ("valid-evidence-shadow-delta.json", "shadow_delta"),
]


@pytest.mark.parametrize(("fixture_name", "expected_payload_kind"), V2_FIXTURES)
def test_v2_fixture_verifies_against_go_signed_bytes(
    fixture_name: str, expected_payload_kind: str
) -> None:
    """Each Go-emitted v2 fixture must verify under the Python verifier.

    Proves byte-for-byte JCS preimage parity between the Go reference
    and the Python verifier. A divergence in either side's
    canonicalisation logic surfaces here as a signature mismatch.
    """
    raw = (CONFORMANCE_DIR / fixture_name).read_bytes()
    receipt = json.loads(raw)

    # Sanity: shape matches the v2 envelope.
    assert receipt["record_type"] == "evidence_receipt_v2"
    assert receipt["receipt_version"] == 2
    assert receipt["payload_kind"] == expected_payload_kind
    assert receipt["signature"]["algorithm"] == "ed25519"
    assert receipt["signature"]["key_purpose"] == "receipt-signing"

    result = verify_evidence(
        receipt,
        public_key_hex=RFC8032_TEST1_PUBLIC_HEX,
        expected_signer_key_id=receipt["signature"]["signer_key_id"],
        expected_key_purpose="receipt-signing",
    )
    if not result.valid:
        raise AssertionError(
            f"Go-emitted v2 fixture {fixture_name} failed Python verification: {result.error}"
        )


def test_v2_fixture_rejects_tampered_payload() -> None:
    """A single byte flip in the payload must invalidate the signature.

    Confirms the Python verifier is computing the same JCS preimage as
    Go: if it weren't, a payload tamper might silently pass because the
    preimage shapes diverged.
    """
    raw = (CONFORMANCE_DIR / "valid-evidence-proxy-decision.json").read_bytes()
    receipt = json.loads(raw)
    # Tamper: flip the verdict from "allow" to "block".
    receipt["payload"]["verdict"] = "block"

    result = verify_evidence(
        receipt,
        public_key_hex=RFC8032_TEST1_PUBLIC_HEX,
        expected_signer_key_id=receipt["signature"]["signer_key_id"],
        expected_key_purpose="receipt-signing",
    )
    assert not result.valid, (
        "tampered v2 receipt verified successfully — JCS preimage "
        "parity broken between Go and Python"
    )


def test_v2_fixture_rejects_wrong_key() -> None:
    """A receipt signed by key A must fail when verified against key B.

    Proves the verifier honours the key-pinning contract.
    """
    raw = (CONFORMANCE_DIR / "valid-evidence-proxy-decision.json").read_bytes()
    receipt = json.loads(raw)

    # All-zero public key is not the RFC 8032 test1 public key.
    wrong_key_hex = "00" * 32
    result = verify_evidence(
        receipt,
        public_key_hex=wrong_key_hex,
        expected_signer_key_id=receipt["signature"]["signer_key_id"],
        expected_key_purpose="receipt-signing",
    )
    assert not result.valid, (
        "v2 receipt verified under wrong public key — pin enforcement is broken"
    )
