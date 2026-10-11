"""Offline proof tests for the authoritative Go canonical drift gate."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_go_canonical_contract.py"
SCRIPT_SPEC = importlib.util.spec_from_file_location("check_go_canonical_contract", SCRIPT_PATH)
assert SCRIPT_SPEC is not None
contract_gate = importlib.util.module_from_spec(SCRIPT_SPEC)
assert SCRIPT_SPEC.loader is not None
sys.modules[SCRIPT_SPEC.name] = contract_gate
SCRIPT_SPEC.loader.exec_module(contract_gate)

ContractDriftError = contract_gate.ContractDriftError
ContractFetchError = contract_gate.ContractFetchError
ContractParseError = contract_gate.ContractParseError
FieldSpec = contract_gate.FieldSpec
check_source = contract_gate.check_source
extract_go_contract = contract_gate.extract_go_contract
read_source_arg = contract_gate.read_source_arg

STRUCT_NAME = "actionRecordCanonicalV1"

BASE_GO_SOURCE = """
package receipt

type actionRecordCanonicalV1 struct {
    Version int `json:"version"`
    ActionID string `json:"action_id"`
    ParentActionID string `json:"parent_action_id,omitempty"`
}
"""

EXPECTED_CONTRACT: dict[str, list[FieldSpec]] = {
    STRUCT_NAME: [
        FieldSpec("version", False),
        FieldSpec("action_id", False),
        FieldSpec("parent_action_id", True),
    ]
}


def _check_test_source(source: str) -> None:
    check_source(
        source,
        source_label="test canonical.go",
        expected_contract=EXPECTED_CONTRACT,
        struct_names=(STRUCT_NAME,),
    )


def test_extracts_go_json_field_order_and_omitempty():
    assert extract_go_contract(BASE_GO_SOURCE, struct_names=(STRUCT_NAME,)) == EXPECTED_CONTRACT


def test_gate_fails_when_go_adds_signed_field():
    changed = BASE_GO_SOURCE.replace(
        '    ActionID string `json:"action_id"`\n',
        '    ActionID string `json:"action_id"`\n'
        '    NewSignedField string `json:"new_signed_field,omitempty"`\n',
    )

    with pytest.raises(ContractDriftError) as error:
        _check_test_source(changed)

    assert "+03 new_signed_field omitempty=true" in str(error.value)
    assert "internal/receipt/canonical.go" in str(error.value)


def test_gate_fails_when_go_reorders_signed_fields():
    changed = BASE_GO_SOURCE.replace(
        '    ActionID string `json:"action_id"`\n'
        '    ParentActionID string `json:"parent_action_id,omitempty"`\n',
        '    ParentActionID string `json:"parent_action_id,omitempty"`\n'
        '    ActionID string `json:"action_id"`\n',
    )

    with pytest.raises(ContractDriftError) as error:
        _check_test_source(changed)

    message = str(error.value)
    assert "--- python/actionRecordCanonicalV1" in message
    assert "+++ go/actionRecordCanonicalV1" in message


def test_gate_fails_when_go_omitempty_changes():
    changed = BASE_GO_SOURCE.replace(
        '    ParentActionID string `json:"parent_action_id,omitempty"`\n',
        '    ParentActionID string `json:"parent_action_id"`\n',
    )

    with pytest.raises(ContractDriftError) as error:
        _check_test_source(changed)

    assert "-03 parent_action_id omitempty=true" in str(error.value)
    assert "+03 parent_action_id omitempty=false" in str(error.value)


def test_gate_fails_closed_when_go_shape_is_unrecognised():
    changed = BASE_GO_SOURCE.replace(
        '    ActionID string `json:"action_id"`\n',
        '    ActionID, ParentActionID string `json:"action_id"`\n',
    )

    with pytest.raises(ContractParseError):
        _check_test_source(changed)


def test_gate_fails_closed_when_source_cannot_be_read(tmp_path):
    missing_source = tmp_path / "missing-canonical.go"

    with pytest.raises(ContractFetchError):
        read_source_arg(str(missing_source))


def test_gate_rejects_a_newly_added_go_canonical_projection():
    """A NEW *CanonicalV1 struct on the Go side must fail the gate.

    The parser originally walked a predeclared list of struct names, which made
    the unexpected-struct branch unreachable: a signing projection added on the
    Go side was skipped in silence and the gate passed while this package had no
    counterpart for it. Structs are discovered now, so the branch can fire.
    """
    changed = BASE_GO_SOURCE + (
        "\ntype brandNewThingCanonicalV1 struct {\n"
        '    SecretField string `json:"secret_field"`\n'
        "}\n"
    )

    with pytest.raises(ContractDriftError) as excinfo:
        _check_test_source(changed)

    assert "brandNewThingCanonicalV1" in str(excinfo.value)


# --- ReceiptGroupBinding: signed nested struct declared in session_control.go ---

check_sources = contract_gate.check_sources
BINDING_STRUCT = "ReceiptGroupBinding"

BASE_SESSION_CONTROL_SOURCE = """
package receipt

type SessionOpen struct {
    GroupBinding *ReceiptGroupBinding `json:"group_binding,omitempty"`
}

type ReceiptGroupBinding struct {
    GroupID    string `json:"group_id"`
    ShardIndex int    `json:"shard_index"`
    SessionID  string `json:"session_id"`
}
"""

TWO_SOURCE_EXPECTED: dict[str, list[FieldSpec]] = {
    **EXPECTED_CONTRACT,
    BINDING_STRUCT: [
        FieldSpec("group_id", False),
        FieldSpec("shard_index", False),
        FieldSpec("session_id", False),
    ],
}


def _check_two_sources(session_control: str) -> None:
    check_sources(
        [(BASE_GO_SOURCE, (STRUCT_NAME,)), (session_control, (BINDING_STRUCT,))],
        source_label="test canonical.go + session_control.go",
        expected_contract=TWO_SOURCE_EXPECTED,
    )


def test_two_source_gate_passes_on_matching_binding():
    _check_two_sources(BASE_SESSION_CONTROL_SOURCE)


def test_two_source_gate_fails_when_go_adds_binding_field():
    changed = BASE_SESSION_CONTROL_SOURCE.replace(
        '    SessionID  string `json:"session_id"`\n',
        '    SessionID  string `json:"session_id"`\n    Extra string `json:"extra"`\n',
    )
    with pytest.raises(ContractDriftError) as excinfo:
        _check_two_sources(changed)
    assert "+04 extra omitempty=false" in str(excinfo.value)


def test_two_source_gate_fails_when_go_removes_binding_field():
    changed = BASE_SESSION_CONTROL_SOURCE.replace(
        '    ShardIndex int    `json:"shard_index"`\n', ""
    )
    with pytest.raises(ContractDriftError) as excinfo:
        _check_two_sources(changed)
    assert "shard_index" in str(excinfo.value)


def test_two_source_gate_fails_when_go_reorders_binding_fields():
    changed = BASE_SESSION_CONTROL_SOURCE.replace(
        '    GroupID    string `json:"group_id"`\n    ShardIndex int    `json:"shard_index"`\n',
        '    ShardIndex int    `json:"shard_index"`\n    GroupID    string `json:"group_id"`\n',
    )
    with pytest.raises(ContractDriftError):
        _check_two_sources(changed)


def test_two_source_gate_fails_when_binding_becomes_omitempty():
    changed = BASE_SESSION_CONTROL_SOURCE.replace('json:"group_id"', 'json:"group_id,omitempty"')
    with pytest.raises(ContractDriftError):
        _check_two_sources(changed)


def test_two_source_gate_fails_closed_when_binding_struct_missing():
    with pytest.raises(ContractParseError, match="ReceiptGroupBinding"):
        _check_two_sources("package receipt\n")


def test_python_contract_includes_group_binding():
    assert BINDING_STRUCT in contract_gate.python_contract()


def test_fetch_mode_reads_both_sources_at_one_resolved_sha(monkeypatch, capsys):
    sha = "a" * 40
    urls: list[str] = []

    def fake_request(url: str, *, timeout: float) -> bytes:
        urls.append(url)
        if url.startswith("https://api.github.com/"):
            return json.dumps({"sha": sha}).encode()
        raise ContractFetchError(f"offline test refused {url}")

    monkeypatch.setattr(contract_gate, "_request", fake_request)
    assert contract_gate.main(["--ref", "main"]) == 1
    assert "offline test refused" in capsys.readouterr().err
    assert urls[1].endswith(f"/{sha}/internal/receipt/canonical.go")


def test_fetch_mode_refuses_when_session_control_fetch_fails(monkeypatch, capsys):
    sha = "b" * 40

    def fake_request(url: str, *, timeout: float) -> bytes:
        if url.startswith("https://api.github.com/"):
            return json.dumps({"sha": sha}).encode()
        if url.endswith("canonical.go"):
            return b"package receipt\n"
        raise ContractFetchError(f"offline test refused {url}")

    monkeypatch.setattr(contract_gate, "_request", fake_request)
    assert contract_gate.main(["--ref", "main"]) == 1
    err = capsys.readouterr().err
    assert f"/{sha}/internal/receipt/session_control.go" in err


def test_local_mode_requires_both_sources(tmp_path, capsys):
    canonical = tmp_path / "canonical.go"
    canonical.write_text(BASE_GO_SOURCE)
    assert contract_gate.main(["--source", str(canonical)]) == 1
    assert "must be given together" in capsys.readouterr().err
    control = tmp_path / "session_control.go"
    control.write_text(BASE_SESSION_CONTROL_SOURCE)
    assert contract_gate.main(["--session-control-source", str(control)]) == 1


def test_local_mode_refuses_missing_session_control_file(tmp_path, capsys):
    canonical = tmp_path / "canonical.go"
    canonical.write_text(BASE_GO_SOURCE)
    rc = contract_gate.main(
        ["--source", str(canonical), "--session-control-source", str(tmp_path / "nope.go")]
    )
    assert rc == 1
    assert "failed to read Go source" in capsys.readouterr().err
