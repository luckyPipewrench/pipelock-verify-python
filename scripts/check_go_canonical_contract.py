"""Check pipelock-verify's v1 canonical contract against the Go emitter.

The fast pytest guard in ``tests/test_field_drift.py`` compares the Python
implementation to a checked-in mirror. This script is the authoritative drift
gate: it fetches the live Go source, extracts the canonical JSON struct tags,
and fails when the Python projection no longer matches.
"""

from __future__ import annotations

import argparse
import dataclasses
import difflib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping, Sequence

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

GO_OWNER = "luckyPipewrench"
GO_REPO = "pipelock"
GO_SOURCE_PATH = "internal/receipt/canonical.go"
DEFAULT_REF = "main"

GO_STRUCTS: tuple[str, ...] = (
    "actionRecordCanonicalV1",
    "taintSourceRefCanonicalV1",
    "keyTransitionCanonicalV1",
    "sessionControlCanonicalV1",
    "sessionOpenCanonicalV1",
    "sessionHeartbeatCanonicalV1",
    "sessionCloseCanonicalV1",
    "redactionSummaryCanonicalV1",
    "shieldSummaryCanonicalV1",
)

STRUCT_RE = re.compile(r"^type\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+struct\s*\{\s*$")
FIELD_RE = re.compile(
    r"^(?P<name>[A-Z][A-Za-z0-9_]*)\s+(?P<type>.+?)\s+`json:\"(?P<tag>[^\"]+)\"`"
    r"(?:\s*//.*)?$"
)
COMMENT_RE = re.compile(r"^\s*(?://.*)?$")
COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclasses.dataclass(frozen=True, slots=True)
class FieldSpec:
    json_name: str
    omitempty: bool

    def render(self, index: int) -> str:
        return f"{index:02d} {self.json_name} omitempty={str(self.omitempty).lower()}"


class ContractCheckError(RuntimeError):
    """Base class for fail-closed contract check errors."""


class ContractFetchError(ContractCheckError):
    """Raised when the Go source cannot be resolved or fetched."""


class ContractParseError(ContractCheckError):
    """Raised when the Go source shape is not recognised."""


class ContractDriftError(ContractCheckError):
    """Raised when the extracted Go contract differs from Python."""


def _strip_nested_kind(fields: Sequence[tuple[str, bool, str | None]]) -> list[FieldSpec]:
    return [FieldSpec(json_name, omitempty) for json_name, omitempty, _nested_kind in fields]


def python_contract() -> dict[str, list[FieldSpec]]:
    """Return the Python v1 contract in Go canonical struct names.

    Imported here, from THIS checkout, rather than at module scope. Running
    `python scripts/<name>.py` puts scripts/ on sys.path and the repository root
    nowhere, so a top-level import either fails outright (CI, where nothing is
    installed) or silently reads an unrelated installed copy and reports a pass
    that means nothing.
    """

    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

    from pipelock_verify._canonical import (
        _ACTION_RECORD_FIELDS,
        _KEY_TRANSITION_FIELDS,
        _REDACTION_FIELDS,
        _SESSION_CLOSE_FIELDS,
        _SESSION_CONTROL_FIELDS,
        _SESSION_HEARTBEAT_FIELDS,
        _SESSION_OPEN_FIELDS,
        _SHIELD_FIELDS,
        _TAINT_SOURCE_FIELDS,
    )

    return {
        "actionRecordCanonicalV1": _strip_nested_kind(_ACTION_RECORD_FIELDS),
        "taintSourceRefCanonicalV1": _strip_nested_kind(_TAINT_SOURCE_FIELDS),
        "keyTransitionCanonicalV1": _strip_nested_kind(_KEY_TRANSITION_FIELDS),
        "sessionControlCanonicalV1": _strip_nested_kind(_SESSION_CONTROL_FIELDS),
        "sessionOpenCanonicalV1": _strip_nested_kind(_SESSION_OPEN_FIELDS),
        "sessionHeartbeatCanonicalV1": _strip_nested_kind(_SESSION_HEARTBEAT_FIELDS),
        "sessionCloseCanonicalV1": _strip_nested_kind(_SESSION_CLOSE_FIELDS),
        "redactionSummaryCanonicalV1": _strip_nested_kind(_REDACTION_FIELDS),
        "shieldSummaryCanonicalV1": _strip_nested_kind(_SHIELD_FIELDS),
    }


def _request(url: str, *, timeout: float) -> bytes:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "pipelock-verify-canonical-contract-gate",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except (OSError, urllib.error.URLError) as exc:
        raise ContractFetchError(f"failed to fetch {url}: {exc}") from exc


def resolve_ref(ref: str, *, timeout: float) -> str:
    """Resolve a branch or tag to a commit SHA so the later raw fetch is pinned."""

    if COMMIT_SHA_RE.fullmatch(ref):
        return ref
    url = f"https://api.github.com/repos/{GO_OWNER}/{GO_REPO}/commits/{ref}"
    raw = _request(url, timeout=timeout)
    try:
        payload = json.loads(raw.decode("utf-8"))
        sha = payload["sha"]
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractFetchError(f"could not resolve Go ref {ref!r} from {url}") from exc
    if not isinstance(sha, str) or not COMMIT_SHA_RE.fullmatch(sha):
        raise ContractFetchError(f"Go ref {ref!r} resolved to invalid commit SHA {sha!r}")
    return sha


def fetch_go_source(ref: str, *, timeout: float) -> tuple[str, str]:
    """Fetch canonical.go at a concrete commit and return ``(source, sha)``."""

    resolved_sha = resolve_ref(ref, timeout=timeout)
    url = f"https://raw.githubusercontent.com/{GO_OWNER}/{GO_REPO}/{resolved_sha}/{GO_SOURCE_PATH}"
    raw = _request(url, timeout=timeout)
    try:
        return raw.decode("utf-8"), resolved_sha
    except UnicodeDecodeError as exc:
        raise ContractFetchError(f"Go source {url} is not valid UTF-8") from exc


def read_source_arg(source: str) -> tuple[str, str]:
    if source == "-":
        return sys.stdin.read(), "stdin"
    try:
        with open(source, encoding="utf-8") as handle:
            return handle.read(), source
    except OSError as exc:
        raise ContractFetchError(f"failed to read Go source {source}: {exc}") from exc


def extract_go_contract(
    source: str,
    *,
    struct_names: Iterable[str] = GO_STRUCTS,
) -> dict[str, list[FieldSpec]]:
    """Extract JSON field order and omitempty semantics from canonical structs."""

    wanted = tuple(struct_names)
    contract: dict[str, list[FieldSpec]] = {}
    lines = source.splitlines()
    index = 0
    while index < len(lines):
        match = STRUCT_RE.match(lines[index].strip())
        if not match:
            index += 1
            continue
        struct_name = match.group("name")
        index += 1
        body: list[str] = []
        while index < len(lines) and lines[index].strip() != "}":
            body.append(lines[index])
            index += 1
        if index >= len(lines):
            raise ContractParseError(f"unterminated Go struct {struct_name}")
        if struct_name in wanted:
            contract[struct_name] = _parse_struct_fields(struct_name, body)
        index += 1

    missing = [struct_name for struct_name in wanted if struct_name not in contract]
    if missing:
        joined = ", ".join(missing)
        raise ContractParseError(f"missing expected canonical Go struct(s): {joined}")
    return contract


def _parse_struct_fields(struct_name: str, body: Sequence[str]) -> list[FieldSpec]:
    fields: list[FieldSpec] = []
    for offset, raw_line in enumerate(body, start=1):
        line = raw_line.strip()
        if COMMENT_RE.fullmatch(line):
            continue
        match = FIELD_RE.match(line)
        if not match:
            raise ContractParseError(
                f"unrecognised field declaration in {struct_name} line {offset}: {raw_line!r}"
            )
        tag = match.group("tag")
        parts = tag.split(",")
        json_name = parts[0]
        options = set(parts[1:])
        if not json_name or json_name == "-":
            raise ContractParseError(
                f"unsupported json tag in {struct_name} line {offset}: {tag!r}"
            )
        unsupported = options - {"omitempty"}
        if unsupported:
            joined = ", ".join(sorted(unsupported))
            raise ContractParseError(
                f"unsupported json tag option(s) in {struct_name} line {offset}: {joined}"
            )
        fields.append(FieldSpec(json_name=json_name, omitempty="omitempty" in options))
    if not fields:
        raise ContractParseError(f"canonical Go struct {struct_name} has no JSON fields")
    return fields


def diff_contracts(
    go_contract: Mapping[str, Sequence[FieldSpec]],
    expected_contract: Mapping[str, Sequence[FieldSpec]],
) -> list[str]:
    diffs: list[str] = []
    for struct_name, expected_fields in expected_contract.items():
        actual_fields = go_contract.get(struct_name)
        if actual_fields is None:
            diffs.append(f"Go contract missing parsed struct {struct_name}")
            continue
        if list(actual_fields) == list(expected_fields):
            continue
        expected_lines = [
            field.render(index) for index, field in enumerate(expected_fields, start=1)
        ]
        actual_lines = [field.render(index) for index, field in enumerate(actual_fields, start=1)]
        diffs.extend(
            difflib.unified_diff(
                expected_lines,
                actual_lines,
                fromfile=f"python/{struct_name}",
                tofile=f"go/{struct_name}",
                lineterm="",
            )
        )
    extra = sorted(set(go_contract) - set(expected_contract))
    if extra:
        joined = ", ".join(extra)
        diffs.append(f"Go contract has unexpected parsed struct(s): {joined}")
    return diffs


def check_source(
    source: str,
    *,
    source_label: str,
    expected_contract: Mapping[str, Sequence[FieldSpec]] | None = None,
    struct_names: Iterable[str] = GO_STRUCTS,
) -> None:
    expected = expected_contract if expected_contract is not None else python_contract()
    go_contract = extract_go_contract(source, struct_names=struct_names)
    diffs = diff_contracts(go_contract, expected)
    if diffs:
        details = "\n".join(diffs)
        raise ContractDriftError(
            "Go canonical v1 signing projection drifted from pipelock-verify.\n"
            f"Go source: {source_label}\n"
            f"Inspect {GO_SOURCE_PATH}; update pipelock_verify/_canonical.py and the "
            "checked-in mirror tests together.\n\n"
            f"{details}"
        )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fail closed if pipelock-verify's v1 canonical projection drifts from "
            "the Go internal/receipt/canonical.go emitter."
        )
    )
    parser.add_argument(
        "--ref",
        default=os.environ.get("PIPELOCK_GO_REF", DEFAULT_REF),
        help=(
            "Go branch, tag, or 40-character commit SHA to check. Branches/tags are "
            "resolved to a concrete commit before fetching canonical.go."
        ),
    )
    parser.add_argument(
        "--source",
        help="Read Go source from this file path instead of fetching. Use '-' for stdin.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="Network timeout in seconds for each GitHub request.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.source:
            source, source_label = read_source_arg(args.source)
        else:
            source, resolved_sha = fetch_go_source(args.ref, timeout=args.timeout)
            source_label = (
                f"github.com/{GO_OWNER}/{GO_REPO}@{resolved_sha}:{GO_SOURCE_PATH} "
                f"(requested ref {args.ref!r})"
            )
        check_source(source, source_label=source_label)
    except ContractCheckError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: Python canonical v1 contract matches {source_label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
