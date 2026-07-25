"""Offline proof tests for the authoritative Go canonical drift gate."""

from __future__ import annotations

import importlib.util
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
