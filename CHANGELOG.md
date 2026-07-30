# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-07-30

### Added

- **Old-key-endorsed ActionReceipt rotation verification.** `verify_chain()`
  accepts a pinned root, signed recorder session, and rotation
  endorsements. It verifies each endorsement under the retiring key, binds it
  to the exact prior sequence and tail hash, and authorizes the successor key.
  Missing, altered, duplicate, cross-session, replayed, boundary-mismatched,
  unknown-field, duplicate-key, and trailing-token endorsements fail closed.
- **Rotation endorsement API and CLI.** `load_rotation_endorsement()` and
  `verify_rotation_endorsement()` expose strict standalone verification. The
  CLI accepts repeatable `--rotation-endorsement FILE` plus `--session-id`.
- **Go-generated rotation conformance fixtures.** Python verifies the same
  rotated chain and endorsement consumed by the Go, TypeScript, and Rust
  implementations.

## [0.3.0] - 2026-07-24

### Fixed

- **Signature verification against current Pipelock releases.** The v1 canonical
  projection omitted nine fields the emitter signs, so every receipt produced by
  a current Pipelock failed verification. `decision_phase` is emitted on ordinary
  proxy decisions, which made the break total rather than partial. Restores
  `decision_phase`, `defer_id`, `resolution_policy`, `resolution_source`,
  `session_id`, `session_id_original`, `run_nonce`, `key_transition` and
  `session_control` in the emitter's declaration order, with the nested ordering
  and omitempty semantics the frozen signing projection uses.

- **Chain hash coverage of the `ext` bag.** The receipt envelope omitted `ext`,
  but the emitter's receipt hash is a digest over the marshalled receipt and
  `ext` is a marshalled field. The chain hash was therefore identical with and
  without `ext`, and `ext` could be attached or altered without moving the hash
  the chain commits to. `ext` is now included, ordered last, and its original
  bytes are preserved from the source JSON, since the emitter writes it verbatim
  and re-serializing it changes key order, number spelling and escaping.

- **Seven classes of chain that verified here and are rejected by the emitter.**
  Malformed `session_control`, out-of-range `chain_seq`, unknown signed fields,
  malformed nested objects, misplaced `key_transition` markers, restart opens not
  bound to the prior tail, and unbounded integer counters were all accepted with
  a valid signature.

### Added

- **Bound session-open genesis validation.** Chains anchored with the `g1:`
  prefix are checked against the genesis digest the emitter computes, including
  the run and open nonces, policy hash, signer key epoch, and the posture and
  containment binding.

- **A regression fixture captured from a real release binary**, covering session
  open, heartbeat and close, evidence receipts, transcript root and checkpoint
  records, with the root hash pinned to the value the Go verifier independently
  computes. Parity is checked against genuine emitter output rather than
  hand-written data that can drift alongside the code it is meant to check.

### Note

0.2.0 was never published to PyPI. Upgrading from 0.1.1 picks up the
EvidenceReceipt v2 support and well-known directory helpers described under
0.2.0 as well as everything above.

## [0.2.0] - 2026-05-01

### Added

- **EvidenceReceipt v2 support.** Full schema parsing and verification for
  the contract-aware receipt envelope introduced in Pipelock v2.4. Includes:
  - All 13 payload kinds: `proxy_decision`, `contract_ratified`,
    `contract_promote_intent`, `contract_promote_committed`,
    `contract_rollback_authorized`, `contract_rollback_committed`,
    `contract_demoted`, `contract_expired`, `contract_drift`,
    `shadow_delta`, `opportunity_missing`, `key_rotation`,
    `contract_redaction_request`.
  - Strict unknown-field rejection at envelope, signature proof, and payload
    levels.
  - Key purpose authority matrix enforcement (rejects valid signatures from
    the wrong purpose).
  - Detached Ed25519 PureEdDSA signature verification with JCS (RFC 8785)
    canonicalization over typed structures.
  - `verify_evidence()` function for direct v2 verification with
    `expected_signer_key_id` and `expected_key_purpose` parameters.
  - `EvidenceVerifyResult` dataclass with v2-specific diagnostic fields.
  - `evidence_receipt_hash()` for v2 chain linkage computation.

- **Version routing in `verify()`.** The existing `verify()` function now
  auto-detects v1 vs v2 receipts by the `record_type` field and dispatches
  to the correct verification path. Unknown record types are rejected with
  a clear error.

- **Well-known directory fetch helper.** `fetch_directory(host)` retrieves
  the signing keyset from `/.well-known/http-message-signatures-directory`
  (RFC 9421). `parse_directory()` parses the keyset from raw JSON.
  `Directory` dataclass with `get_key()` and `public_key_hex()` lookup
  methods.

- **RFC 8785 JCS canonicalization module** (`_jcs.py`). Strict JSON parser
  with duplicate-key rejection, float rejection, trailing-token rejection,
  and NFC normalization. Used by EvidenceReceipt v2 preimage computation.

### Changed

- README updated with v2 documentation, well-known directory example, and
  13-payload-kind authority matrix table. The key-pinning example now uses
  the well-known directory fetch instead of a hardcoded SHA digest.

### Fixed

- Nothing. This is a backward-compatible feature release.

### Backward compatibility

- **No breaking changes.** All v0.1.x callers verifying ActionReceipt v1
  continue to work without modification.
- `verify()` returns `VerifyResult` for both v1 and v2 (v2 fields are
  mapped: `event_id` to `action_id`, `payload_kind` to `action_type`).
- `verify_chain()` is unchanged.
- The `PAYLOAD_KINDS` and `PAYLOAD_AUTHORITY` constants are exported for
  callers that need to inspect the v2 schema programmatically.

## [0.1.1] - 2026-04-25

### Fixed

- Internal version metadata sync.

## [0.1.0] - 2026-04-09

### Added

- Initial release. ActionReceipt v1 verification with Ed25519 signatures,
  chain linkage, flight-recorder unwrapping, and CLI.
