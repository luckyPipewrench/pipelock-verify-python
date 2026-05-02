"""Pipelock receipt verifier.

Verifies Ed25519-signed receipts emitted by the Pipelock mediator. Supports
both **ActionReceipt v1** (legacy) and **EvidenceReceipt v2** (contract-aware).

Typical usage::

    import pipelock_verify

    # Single receipt (auto-detects v1 vs v2 by record_type).
    result = pipelock_verify.verify(receipt_json)
    if not result.valid:
        raise SystemExit(f"bad receipt: {result.error}")

    # EvidenceReceipt v2 with key purpose enforcement.
    result = pipelock_verify.verify_evidence(
        receipt_dict,
        public_key_hex="...",
        expected_key_purpose="receipt-signing",
    )

    # Receipt chain from a flight recorder JSONL file.
    chain = pipelock_verify.verify_chain("evidence-proxy-0.jsonl")
    if not chain.valid:
        raise SystemExit(f"chain broken at seq {chain.broken_at_seq}: {chain.error}")

    # Fetch signing keys from the well-known directory.
    directory = pipelock_verify.fetch_directory("pipelab.org")
    key_hex = directory.public_key_hex()

Trust anchors are opt-in. Pass ``public_key_hex`` to pin a specific signer,
or leave it empty to trust the key embedded in the receipt (chain mode then
enforces signer consistency across every receipt in the file).

Wire format: see https://pipelab.org/learn/action-receipt-spec/ for field
layout, canonicalization rules, and the exact signing input.
"""

from ._directory import (
    Directory,
    DirectoryFetchError,
    DirectoryKey,
    fetch_directory,
    parse_directory,
)
from ._evidence import (
    PAYLOAD_AUTHORITY,
    PAYLOAD_KINDS,
    EvidenceVerifyResult,
    evidence_receipt_hash,
    verify_evidence,
)
from ._verify import (
    ChainResult,
    InvalidReceiptError,
    VerifyResult,
    verify,
    verify_chain,
)

__version__ = "0.2.0"

__all__ = [
    "PAYLOAD_AUTHORITY",
    "PAYLOAD_KINDS",
    "ChainResult",
    "Directory",
    "DirectoryFetchError",
    "DirectoryKey",
    "EvidenceVerifyResult",
    "InvalidReceiptError",
    "VerifyResult",
    "__version__",
    "evidence_receipt_hash",
    "fetch_directory",
    "parse_directory",
    "verify",
    "verify_chain",
    "verify_evidence",
]
