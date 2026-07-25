#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""AI-powered PR review for the pipelock-verify Python package.

Triggered by /review comments on PRs. Supports multiple review modes:
  /review       - Security and correctness review (smaller model, default)
  /review deep  - Deeper review (larger model)
  /review tests - Test coverage and boundary analysis
  /review docs  - Documentation accuracy check

Requires environment variables:
  GITHUB_TOKEN       - GitHub token (provided by Actions)
  REPO               - owner/repo
  PR_NUMBER          - PR number
  REVIEW_MODE        - "default", "deep", "tests", or "docs"

LLM configuration (one of):
  LITELLM_BASE_URL + LITELLM_API_KEY  - LiteLLM proxy
  OPENAI_API_KEY                       - Direct OpenAI API

Model selection:
  PR_REVIEW_MODEL_FAST  - Model for default/tests/docs (default: gpt-5.4-mini)
  PR_REVIEW_MODEL_DEEP  - Model for /review deep (default: gpt-5.5)

The PR_REVIEW_MODEL_FAST env var keeps its name for backwards compatibility
with any existing repo-secrets overrides; the user-facing /review fast
alias was dropped 2026-04-23 because the default mode is fast enough.
"""

import json
import os
import sys

import requests

# --- Constants ---

MAX_DIFF_CHARS = 100_000
DEFAULT_MODEL_FAST = "gpt-5.4-mini"
DEFAULT_MODEL_DEEP = "gpt-5.5"
DEFAULT_TEMPERATURE = 0.2
DEFAULT_MAX_COMPLETION_TOKENS = 4096
DEEP_MAX_COMPLETION_TOKENS = 25000
DEFAULT_LLM_TIMEOUT_SECONDS = 120
DEEP_LLM_TIMEOUT_SECONDS = 300
FAST_REASONING_EFFORT = "low"
DEEP_REASONING_EFFORT = "medium"


class LLMReviewError(RuntimeError):
    """Raised when the LLM call completed but did not produce a usable review."""


PROMPT_SECURITY = """You are reviewing a pull request for pipelock-verify, the Python verifier for Pipelock action receipts: Ed25519-signed, hash-chained records that an independent party uses to check what an AI agent actually did.

This library's defining property is BYTE-EXACT PARITY with the Go emitter. The signing input is the SHA-256 of a canonical JSON projection of the action record, reproduced to match Go's encoding/json byte for byte. Any divergence in field set, field order, omitempty semantics, escaping, or number spelling changes the hash and breaks verification. There is no slack.

Two failure directions both matter, and they are not symmetric:
- FAIL-OPEN: accepting something Go rejects. A receipt that verifies here but not in Go means this tool blesses evidence the emitter considers invalid. Treat as high severity.
- FAIL-CLOSED: rejecting something Go accepts. This breaks honest operators and makes the tool untrustworthy in the other direction. Still a real defect, usually medium.

Flag:
- any change to the canonical projection: added, removed, reordered, or re-typed fields, and whether omitempty matches Go
- signature or chain-hash construction changes, including what is and is not covered by each
- validation that accepts a shape Go's strict Unmarshal would reject, or rejects one it accepts
- parser-differential surfaces: duplicate keys, trailing tokens, unicode normalization, HTML escaping, integer bounds, float spelling, empty versus absent
- anywhere parsed-and-re-serialized data is used where the producer's original bytes are what actually get hashed
- guards that cannot be reached, or that no test would catch the removal of
- error paths that surface as tracebacks rather than a clean invalid result on attacker-supplied input

Do not waste time on style nits.
For each finding, include:
1. severity: high, medium, or low
2. file and function
3. why it matters, and which direction it fails
4. a concrete fix

If there are no material issues, say exactly: No material security or correctness issues found in this diff."""

PROMPT_TESTS = """You are reviewing the TEST COVERAGE of a pull request for pipelock-verify, a Python verifier for Ed25519-signed, hash-chained Pipelock receipts.

The single most important question: WOULD THIS TEST FAIL IF THE THING IT GUARDS WERE DELETED? A test that passes whether or not the guard exists is worse than no test, because it reports safety it does not provide. Say so explicitly wherever you suspect it.

For each code change, check:

1. **Vacuity**: for every new guard or validation, is there a test that fails when that guard is removed? If the guard is only reachable through one entry point, does a test actually use that entry point?
2. **Parity, not just validity**: chain tests that assert only "valid" do not catch a divergence in what the chain commits to. Is the root hash or canonical output pinned to an independently computed value?
3. **Real emitter output**: is parity proven against a captured real chain, or only against hand-written data that can drift alongside the code it checks?
4. **Both directions**: for a new rejection, is there a positive test proving legitimate input still passes? Over-tightening is a real defect.
5. **Boundaries**: integer limits including int64 and uint64 edges, empty versus absent, null, empty object and array, non-sorted keys, unicode and HTML-escapable characters, very large values.
6. **Error paths**: are new error returns exercised?

For each gap:
1. severity: high (untested guard or unproven parity), medium (untested boundary), low (nice-to-have)
2. file and line
3. the specific missing case
4. a concrete test to add, including input and expected result

If coverage is adequate, say exactly: Test coverage is adequate for this diff."""

PROMPT_DOCS = """You are reviewing a pull request for pipelock-verify for DOCUMENTATION ACCURACY.

Check every claim in the diff against the code:

1. **Contract claims**: statements about which fields are signed, what the chain hash covers, or how canonicalization works must match the actual implementation and the Go source it mirrors.
2. **Source-of-truth pointers**: comments naming a Go file or struct as the contract must name the file that actually defines it. A pointer to the wrong file is how drift goes unnoticed.
3. **Capability claims**: if docs say something is verified, enforced, or guaranteed, confirm the code does it. Flag anything that overstates what an offline verifier can prove.
4. **Stated limitations**: known gaps should be documented plainly rather than implied or omitted.
5. **Examples**: sample code and CLI invocations must actually run as written.
6. **Stale references**: removed functions, renamed parameters, old behavior.

For each issue:
1. severity: high (wrong claim about what is verified), medium (stale or misleading), low (unclear)
2. file and line
3. what it says versus what the code shows
4. the correct statement

If documentation is accurate, say exactly: Documentation accurately reflects the codebase in this diff."""


def get_pr_diff(repo: str, pr_number: str, token: str) -> str:
    """Fetch the PR diff from GitHub."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.diff",
    }
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.text


def truncate_diff(diff: str, max_chars: int = MAX_DIFF_CHARS) -> str:
    """Truncate diff to stay within token limits."""
    if len(diff) <= max_chars:
        return diff
    truncated = diff[:max_chars]
    return truncated + f"\n\n... (diff truncated at {max_chars} chars, {len(diff)} total)"


def model_supports_custom_temperature(model: str) -> bool:
    """Return whether chat completions should send a non-default temperature."""
    normalized = model.strip().lower()
    model_name = normalized.rsplit("/", 1)[-1]
    return not model_name.startswith(("gpt-5", "o1", "o3", "o4"))


def model_supports_reasoning_effort(model: str) -> bool:
    """Return whether chat completions should pin reasoning effort."""
    normalized = model.strip().lower()
    model_name = normalized.rsplit("/", 1)[-1]
    return model_name.startswith(("gpt-5", "o1", "o3", "o4"))


def build_llm_payload(
    model: str,
    system_prompt: str,
    diff: str,
    *,
    max_completion_tokens: int = DEFAULT_MAX_COMPLETION_TOKENS,
    reasoning_effort: str = FAST_REASONING_EFFORT,
) -> dict:
    """Build the chat completions payload for the selected review model."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"Review this pull request diff:\n\n```diff\n{diff}\n```",
            },
        ],
        "max_completion_tokens": max_completion_tokens,
    }
    if model_supports_custom_temperature(model):
        payload["temperature"] = DEFAULT_TEMPERATURE
    if model_supports_reasoning_effort(model):
        payload["reasoning_effort"] = reasoning_effort
    return payload


def summarize_usage(data: dict) -> str:
    """Return compact token usage details for operator-visible errors."""
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return "usage unavailable"
    details = usage.get("completion_tokens_details") or {}
    parts = [
        f"prompt={usage.get('prompt_tokens', 'unknown')}",
        f"completion={usage.get('completion_tokens', 'unknown')}",
        f"total={usage.get('total_tokens', 'unknown')}",
    ]
    if isinstance(details, dict) and "reasoning_tokens" in details:
        parts.append(f"reasoning={details['reasoning_tokens']}")
    return ", ".join(parts)


def extract_chat_content(data: dict) -> str:
    """Extract visible text from a chat-completions response."""
    choices = data.get("choices", [])
    if not choices:
        raise LLMReviewError("LLM returned no choices. Raw response: " + json.dumps(data)[:500])

    choice = choices[0]
    message = choice.get("message", {})
    content = message.get("content", "")
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    if isinstance(content, str) and content.strip():
        if choice.get("finish_reason") == "length":
            content += (
                "\n\n> **Warning:** Review output was truncated by the model "
                f"completion limit ({summarize_usage(data)}). Treat this as an "
                "incomplete review and rerun with a narrower diff if needed."
            )
        return content

    finish_reason = choice.get("finish_reason", "unknown")
    raise LLMReviewError(
        f"LLM returned empty content (finish_reason={finish_reason}; {summarize_usage(data)})."
    )


def call_llm(diff: str, mode: str, system_prompt: str) -> str:
    """Send the diff to the LLM and return the review."""
    litellm_url = os.environ.get("LITELLM_BASE_URL", "")
    litellm_key = os.environ.get("LITELLM_API_KEY", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")

    if mode == "deep":
        model = os.environ.get("PR_REVIEW_MODEL_DEEP") or DEFAULT_MODEL_DEEP
    else:
        model = os.environ.get("PR_REVIEW_MODEL_FAST") or DEFAULT_MODEL_FAST

    if litellm_url and litellm_key:
        api_url = litellm_url.rstrip("/") + "/chat/completions"
        bearer = litellm_key
    elif openai_key:
        api_url = "https://api.openai.com/v1/chat/completions"
        bearer = openai_key
    else:
        raise LLMReviewError(
            "No LLM API configured. Set LITELLM_BASE_URL + LITELLM_API_KEY "
            "or OPENAI_API_KEY in repo secrets."
        )

    headers = {
        "Authorization": f"Bearer {bearer}",
        "Content-Type": "application/json",
    }
    is_deep = mode == "deep"
    max_completion_tokens = DEEP_MAX_COMPLETION_TOKENS if is_deep else DEFAULT_MAX_COMPLETION_TOKENS
    reasoning_effort = DEEP_REASONING_EFFORT if is_deep else FAST_REASONING_EFFORT
    payload = build_llm_payload(
        model,
        system_prompt,
        diff,
        max_completion_tokens=max_completion_tokens,
        reasoning_effort=reasoning_effort,
    )

    timeout = DEEP_LLM_TIMEOUT_SECONDS if is_deep else DEFAULT_LLM_TIMEOUT_SECONDS
    resp = requests.post(api_url, headers=headers, json=payload, timeout=timeout)
    if resp.status_code != 200:
        body = resp.text[:500]
        raise LLMReviewError(
            f"LLM API returned {resp.status_code}.\n\n"
            f"**Model:** `{model}`\n\n"
            f"**Response:**\n```\n{body}\n```"
        )
    data = resp.json()
    return extract_chat_content(data)


def post_comment(repo: str, pr_number: str, token: str, body: str) -> None:
    """Post a comment on the PR."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    resp = requests.post(url, headers=headers, json={"body": body}, timeout=30)
    resp.raise_for_status()


def main() -> None:
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("REPO", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    mode = os.environ.get("REVIEW_MODE", "default")

    if not all([gh_token, repo, pr_number]):
        print("Missing required environment variables", file=sys.stderr)
        sys.exit(1)

    print(f"Reviewing PR #{pr_number} in {repo} (mode: {mode})")

    # All other modes need the diff.
    try:
        diff = get_pr_diff(repo, pr_number, gh_token)
    except requests.RequestException as e:
        post_comment(
            repo, pr_number, gh_token, f"**AI Review Error:** Failed to fetch PR diff: {e}"
        )
        sys.exit(1)

    if not diff.strip():
        post_comment(repo, pr_number, gh_token, "**AI Review:** No diff found for this PR.")
        return

    diff = truncate_diff(diff)
    print(f"Diff size: {len(diff)} chars")

    # Select prompt.
    prompts = {
        "default": PROMPT_SECURITY,
        "deep": PROMPT_SECURITY,
        "tests": PROMPT_TESTS,
        "docs": PROMPT_DOCS,
    }
    system_prompt = prompts.get(mode, PROMPT_SECURITY)

    try:
        review = call_llm(diff, mode, system_prompt)
    except (requests.RequestException, LLMReviewError) as e:
        post_comment(repo, pr_number, gh_token, f"**AI Review Error:** {e}")
        sys.exit(1)

    model_name = os.environ.get(
        "PR_REVIEW_MODEL_DEEP" if mode == "deep" else "PR_REVIEW_MODEL_FAST"
    ) or (DEFAULT_MODEL_DEEP if mode == "deep" else DEFAULT_MODEL_FAST)

    mode_labels = {
        "default": "security",
        "deep": "security deep",
        "tests": "test coverage",
        "docs": "docs accuracy",
    }
    label = mode_labels.get(mode, mode)
    # The default mode is invoked as bare `/review`, not `/review default`,
    # so the header omits the suffix in that case to match what the user
    # actually typed.
    cmd = "/review" if mode == "default" else f"/review {mode}"
    header = f"## AI Review: {label} (`{cmd}`)\n\n**Model:** `{model_name}`\n\n---\n\n"
    post_comment(repo, pr_number, gh_token, header + review)
    print("Review posted.")


if __name__ == "__main__":
    main()
