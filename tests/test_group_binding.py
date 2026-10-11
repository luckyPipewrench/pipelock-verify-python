"""session_open.group_binding: signed per-chain compatibility with Go.

Go (pipelock internal/receipt, #1828) signs an optional
``session_open.group_binding`` pointer whose seven fields are never omitempty.
The fixtures are two shards of one Go-written receipt group, copied verbatim
from Go's shared receipt-group corpus (case ``v2-n2-closed``).

Scope boundary: ``verify``/``verify_chain`` authenticate one receipt or one
supplied chain. Accepting a signed binding does NOT prove group membership,
that no shard is missing, open/close manifest integrity, recovery tails or AEL
completeness. Those belong to Go's receipt group verifier, which this package
does not implement.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import pipelock_verify
from pipelock_verify._canonical import canonicalize_action_record, canonicalize_receipt

FIXTURES = Path(__file__).parent / "fixtures"
SHARD0 = FIXTURES / "go_group_shard0.jsonl"
SHARD1 = FIXTURES / "go_group_shard1.jsonl"
GO_KEY = (FIXTURES / "go_group_shards.pub").read_text().strip()

_BINDING = {
    "group_id": "g",
    "shard_index": 0,
    "session_id": "s",
    "open_manifest_sha256": "a" * 64,
    "signer_key": "b" * 64,
    "previous_group_id": "",
    "previous_open_manifest_sha256": "",
}


def _entries(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _open_entry(entries: list[dict[str, Any]]) -> dict[str, Any]:
    for entry in entries:
        ctrl = (entry.get("detail") or {}).get("action_record", {}).get("session_control")
        if ctrl and ctrl.get("kind") == "session_open":
            return entry
    raise AssertionError("fixture has no session_open receipt")


def _binding(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return _open_entry(entries)["detail"]["action_record"]["session_control"]["open"][
        "group_binding"
    ]


def _write(tmp_path: Path, entries: list[dict[str, Any]]) -> Path:
    out = tmp_path / "shard.jsonl"
    out.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries))
    return out


@pytest.mark.parametrize("shard", [SHARD0, SHARD1])
def test_go_signed_grouped_shard_verifies_per_chain(shard):
    result = pipelock_verify.verify_chain(shard, public_key_hex=GO_KEY)
    assert result.valid, result.error
    assert result.receipt_count == 3


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("group_id", "ffffffffffffffffffffffffffffffff"),
        ("shard_index", 1),
        ("session_id", "proxy.run.forged"),
        ("open_manifest_sha256", "0" * 64),
        ("signer_key", "0" * 64),
        ("previous_group_id", "forged"),
        ("previous_open_manifest_sha256", "0" * 64),
    ],
)
def test_tampered_go_binding_field_fails_signature(tmp_path, field, value):
    entries = _entries(SHARD0)
    _binding(entries)[field] = value
    result = pipelock_verify.verify_chain(_write(tmp_path, entries), public_key_hex=GO_KEY)
    assert not result.valid
    assert "signature" in (result.error or "")


def test_stripped_go_binding_fails_signature(tmp_path):
    entries = _entries(SHARD0)
    del _open_entry(entries)["detail"]["action_record"]["session_control"]["open"]["group_binding"]
    result = pipelock_verify.verify_chain(_write(tmp_path, entries), public_key_hex=GO_KEY)
    assert not result.valid


def test_binding_swapped_from_sibling_shard_fails_signature(tmp_path):
    entries = _entries(SHARD0)
    _open_entry(entries)["detail"]["action_record"]["session_control"]["open"]["group_binding"] = (
        _binding(_entries(SHARD1))
    )
    result = pipelock_verify.verify_chain(_write(tmp_path, entries), public_key_hex=GO_KEY)
    assert not result.valid


def test_per_chain_acceptance_is_not_group_completeness():
    # One shard of a two-shard group verifies on its own: verify_chain never
    # sees the sibling shard or the group manifests, so a valid result here
    # must not be read as complete-group verification.
    result = pipelock_verify.verify_chain(SHARD0, public_key_hex=GO_KEY)
    assert result.valid
    assert not hasattr(pipelock_verify, "verify_receipt_group")


# Self-signed receipts use the conformance test key. Helpers live here, not in
# another test module, so the plain ``pytest`` entry point can collect this file.
_TEST_KEY = json.loads((Path(__file__).parent / "conformance" / "test-key.json").read_text())


def _sign(ar: dict[str, Any]) -> dict[str, Any]:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(_TEST_KEY["seed_hex"]))
    sig = priv.sign(hashlib.sha256(canonicalize_action_record(ar)).digest())
    return {
        "version": 1,
        "action_record": ar,
        "signature": "ed25519:" + sig.hex(),
        "signer_key": _TEST_KEY["public_key_hex"],
    }


def _base_ar() -> dict[str, Any]:
    return {
        "version": 1,
        "action_id": "group-binding-0",
        "action_type": "read",
        "timestamp": "2026-04-09T13:50:00Z",
        "principal": "org:test",
        "actor": "agent:test",
        "delegation_chain": ["grant"],
        "target": "https://example.com",
        "side_effect_class": "external_read",
        "reversibility": "reversible",
        "policy_hash": "",
        "verdict": "allow",
        "transport": "https",
        "chain_prev_hash": "genesis",
        "chain_seq": 0,
    }


_FIRST = _sign(_base_ar())
_PRIOR_HASH = hashlib.sha256(canonicalize_receipt(_FIRST)).hexdigest()


def _open_ar(binding: Any) -> dict[str, Any]:
    """A restart session_open bound to ``_FIRST``, carrying ``binding``."""
    ar = _base_ar()
    ar["action_id"] = "group-binding-open"
    ar["timestamp"] = "2026-04-09T13:50:01Z"
    ar["chain_seq"] = 1
    ar["chain_prev_hash"] = _PRIOR_HASH
    ar["run_nonce"] = "run-2"
    ar["session_control"] = {
        "kind": "session_open",
        "open": {
            "run_nonce": "run-2",
            "open_nonce": "open-2",
            "recorder_session": "proxy",
            "policy_hash": "policy",
            "signer_key_epoch": _TEST_KEY["public_key_hex"],
            "heartbeat_seconds": 60,
            "chain_open_seq": 1,
            "prior_chain_head": _PRIOR_HASH,
            "prior_chain_seq": 0,
            "group_binding": binding,
        },
    }
    return ar


def _verify_open(tmp_path: Path, ar: dict[str, Any]) -> Any:
    chain = tmp_path / "chain.jsonl"
    chain.write_text(
        "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in (_FIRST, _sign(ar)))
    )
    return pipelock_verify.verify_chain(chain)


@pytest.mark.parametrize("binding", [None, _BINDING])
def test_self_signed_open_control_verifies(tmp_path, binding):
    # Positive control: proves the self-signed fixtures below reach a valid
    # chain, so their failures and passes are about group_binding alone.
    result = _verify_open(tmp_path, _open_ar(binding))
    assert result.valid, result.error


@pytest.mark.parametrize(
    ("binding", "want"),
    [
        ("not-an-object", "group_binding must be an object"),
        ([], "group_binding must be an object"),
        ({**_BINDING, "extra": "x"}, "group_binding carries unknown signed field(s): ['extra']"),
        ({**_BINDING, "shard_index": "0"}, "shard_index must be an integer"),
        ({**_BINDING, "shard_index": True}, "shard_index must be an integer"),
        ({**_BINDING, "shard_index": 1.5}, "shard_index must be an integer"),
        ({**_BINDING, "shard_index": 2**63}, "shard_index must be an integer"),
        ({**_BINDING, "group_id": 7}, "group_id must be a string"),
        ({**_BINDING, "extra": None}, "group_binding carries unknown signed field(s): ['extra']"),
        ({**_BINDING, "previous_group_id": 0}, "previous_group_id must be a string"),
        ({**_BINDING, "shard_index": -(2**63) - 1}, "shard_index must be an integer"),
    ],
)
def test_malformed_binding_rejected_even_with_valid_signature(tmp_path, binding, want):
    result = _verify_open(tmp_path, _open_ar(binding))
    assert not result.valid
    assert want in (result.error or "")


def test_null_binding_is_ungrouped_like_go_nil_pointer():
    assert canonicalize_action_record(_open_ar(None)) == canonicalize_action_record(
        {
            **_open_ar(None),
            "session_control": {
                **_open_ar(None)["session_control"],
                "open": {
                    k: v
                    for k, v in _open_ar(None)["session_control"]["open"].items()
                    if k != "group_binding"
                },
            },
        }
    )
    assert b"group_binding" not in canonicalize_action_record(_open_ar(None))


def test_missing_binding_fields_sign_as_go_zero_values():
    partial = {k: v for k, v in _BINDING.items() if not k.startswith("previous_")}
    del partial["shard_index"]
    assert canonicalize_action_record(_open_ar(partial)) == canonicalize_action_record(
        _open_ar(_BINDING)
    )


def test_binding_canonical_field_order_matches_go():
    shuffled = dict(reversed(list(_BINDING.items())))
    raw = canonicalize_action_record(_open_ar(shuffled)).decode()
    start = raw.index('"group_binding":')
    positions = [raw.index(f'"{name}":', start) for name in _BINDING]
    assert positions == sorted(positions)


# --- JSON null inside a present binding (Go: null into a typed field keeps zero) ---
# Reproduced against Go main 4ef11fcd: receipt.Unmarshal + VerifyWithKey on the
# Go-signed shard accepts previous_group_id/previous_open_manifest_sha256/
# shard_index set to null (signed values were zero), rejects the signature when
# a non-zero group_id is nulled, and decodes {} to an all-zero binding.


@pytest.mark.parametrize(
    "field", ["previous_group_id", "previous_open_manifest_sha256", "shard_index"]
)
def test_null_for_zero_valued_go_binding_field_still_verifies(tmp_path, field):
    entries = _entries(SHARD0)
    assert _binding(entries)[field] in ("", 0)
    _binding(entries)[field] = None
    result = pipelock_verify.verify_chain(_write(tmp_path, entries), public_key_hex=GO_KEY)
    assert result.valid, result.error


def test_null_for_signed_nonzero_go_binding_field_fails_signature(tmp_path):
    entries = _entries(SHARD0)
    _binding(entries)["group_id"] = None
    result = pipelock_verify.verify_chain(_write(tmp_path, entries), public_key_hex=GO_KEY)
    assert not result.valid
    assert "signature" in (result.error or "")


@pytest.mark.parametrize("replacement", [None, {}])
def test_null_or_empty_whole_go_binding_fails_signature(tmp_path, replacement):
    entries = _entries(SHARD0)
    _open_entry(entries)["detail"]["action_record"]["session_control"]["open"]["group_binding"] = (
        replacement
    )
    result = pipelock_verify.verify_chain(_write(tmp_path, entries), public_key_hex=GO_KEY)
    assert not result.valid
    assert "signature" in (result.error or "")


@pytest.mark.parametrize("field", list(_BINDING))
def test_null_binding_field_signs_as_go_zero(tmp_path, field):
    nulled = {**_BINDING, field: None}
    zeroed = {**_BINDING, field: 0 if field == "shard_index" else ""}
    assert canonicalize_action_record(_open_ar(nulled)) == canonicalize_action_record(
        _open_ar(zeroed)
    )
    result = _verify_open(tmp_path, _open_ar(nulled))
    assert result.valid, result.error


def test_empty_binding_object_signs_all_seven_zero_fields(tmp_path):
    zero = {k: 0 if k == "shard_index" else "" for k in _BINDING}
    assert canonicalize_action_record(_open_ar({})) == canonicalize_action_record(_open_ar(zero))
    result = _verify_open(tmp_path, _open_ar({}))
    assert result.valid, result.error


def test_null_does_not_become_zero_for_legacy_session_open_fields(tmp_path):
    ar = _open_ar(None)
    ar["session_control"]["open"]["contained_uid"] = None
    result = _verify_open(tmp_path, ar)
    assert not result.valid
    assert "contained_uid must be a string" in (result.error or "")
