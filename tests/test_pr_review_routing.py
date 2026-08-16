"""Regression tests for the trusted GitHub PR-review runner's model routing."""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "pr-review.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "pr-review.yaml"


def load_pr_review_module() -> ModuleType:
    """Load the workflow script without executing its CLI entry point."""
    spec = importlib.util.spec_from_file_location("pr_review_routing", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with patch.dict("sys.modules", {"requests": Mock()}):
        spec.loader.exec_module(module)
    return module


class PRReviewRoutingTests(unittest.TestCase):
    def test_model_defaults_and_mode_routing(self):
        module = load_pr_review_module()
        with patch.dict(
            module.os.environ,
            {"PR_REVIEW_MODEL_FAST": "", "PR_REVIEW_MODEL_DEEP": ""},
            clear=False,
        ):
            self.assertEqual(module.DEFAULT_MODEL_FAST, "gpt-5.6-luna")
            self.assertEqual(module.DEFAULT_MODEL_DEEP, "gpt-5.6-terra")
            self.assertEqual(module.model_for_mode("default"), "gpt-5.6-luna")
            self.assertEqual(module.model_for_mode("tests"), "gpt-5.6-luna")
            self.assertEqual(module.model_for_mode("docs"), "gpt-5.6-luna")
            self.assertEqual(module.model_for_mode("deep"), "gpt-5.6-terra")
            self.assertEqual(module.FAST_REASONING_EFFORT, "low")
            self.assertEqual(module.DEEP_REASONING_EFFORT, "xhigh")

    def test_gpt_5_6_payloads_pin_the_requested_reasoning_effort(self):
        module = load_pr_review_module()

        ordinary_payload = module.build_llm_payload(
            module.DEFAULT_MODEL_FAST,
            "system prompt",
            "diff",
            reasoning_effort=module.FAST_REASONING_EFFORT,
        )
        deep_payload = module.build_llm_payload(
            module.DEFAULT_MODEL_DEEP,
            "system prompt",
            "diff",
            reasoning_effort=module.DEEP_REASONING_EFFORT,
            max_completion_tokens=module.DEEP_MAX_COMPLETION_TOKENS,
        )

        self.assertEqual(ordinary_payload["model"], "gpt-5.6-luna")
        self.assertEqual(ordinary_payload["reasoning_effort"], "low")
        self.assertEqual(ordinary_payload["max_completion_tokens"], 8192)
        self.assertEqual(deep_payload["model"], "gpt-5.6-terra")
        self.assertEqual(deep_payload["reasoning_effort"], "xhigh")
        self.assertEqual(deep_payload["max_completion_tokens"], 64000)

    def test_model_repository_variable_overrides(self):
        module = load_pr_review_module()
        with patch.dict(
            module.os.environ,
            {
                "PR_REVIEW_MODEL_FAST": "provider/ordinary-override",
                "PR_REVIEW_MODEL_DEEP": "provider/deep-override",
            },
            clear=False,
        ):
            self.assertEqual(module.model_for_mode("default"), "provider/ordinary-override")
            self.assertEqual(module.model_for_mode("tests"), "provider/ordinary-override")
            self.assertEqual(module.model_for_mode("docs"), "provider/ordinary-override")
            self.assertEqual(module.model_for_mode("deep"), "provider/deep-override")

    def test_empty_repository_variable_overrides_use_python_defaults(self):
        module = load_pr_review_module()
        with patch.dict(
            module.os.environ,
            {"PR_REVIEW_MODEL_FAST": "", "PR_REVIEW_MODEL_DEEP": ""},
            clear=False,
        ):
            self.assertEqual(module.model_for_mode("default"), module.DEFAULT_MODEL_FAST)
            self.assertEqual(module.model_for_mode("deep"), module.DEFAULT_MODEL_DEEP)

    def test_workflow_leaves_model_selection_to_the_shared_reviewer(self):
        # The caller used to choose models through repository variables. The
        # shared reviewer owns that decision now, so a model name appearing
        # here would mean this repository had started diverging from the
        # reviewer it delegates to, which is the drift this change removes.
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIsNone(re.search(r"\bgpt-[0-9]", workflow))
        self.assertNotIn("PR_REVIEW_MODEL_FAST", workflow)
        self.assertNotIn("PR_REVIEW_MODEL_DEEP", workflow)

    def test_workflow_pins_one_immutable_reviewer_and_gates_on_owner(self):
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("github.event.comment.user.login == 'luckyPipewrench'", workflow)
        self.assertIn("github.event.comment.author_association == 'OWNER'", workflow)

        # The pin appears twice and selects two different things: which
        # workflow runs, and which reviewer source it runs. A mismatch runs one
        # version's workflow against another version's code and reports nothing
        # wrong, so equality is the property worth asserting, not presence.
        used = re.search(r"pr-review-reusable\.yaml@([0-9a-f]{40})\b", workflow)
        declared = re.search(r"reviewer_sha:\s*([0-9a-f]{40})\b", workflow)
        self.assertIsNotNone(used, "the reusable workflow must be pinned to a full commit sha")
        self.assertIsNotNone(declared, "reviewer_sha must be a full commit sha")
        self.assertEqual(used.group(1), declared.group(1))

        # A branch or tag can move the reviewer code under the pin, so neither
        # position may carry one.
        self.assertIsNone(re.search(r"pr-review-reusable\.yaml@(?![0-9a-f]{40}\b)\S+", workflow))

        # A caller may only pass secrets the reusable workflow declares. Passing
        # an undeclared one fails at workflow load rather than at review time,
        # which presents as the review simply never running.
        secrets_block = workflow.split("    secrets:", 1)
        self.assertEqual(len(secrets_block), 2, "the caller must map secrets explicitly")
        mapped = set(re.findall(r"^      ([a-z_]+):", secrets_block[1], re.MULTILINE))
        self.assertEqual(mapped, {"review_token", "openai_api_key"})

        runner = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertNotIn("resp.text[:500]", runner)

    def test_response_shape_errors_are_generic_and_fail_closed(self):
        module = load_pr_review_module()

        with self.assertRaises(module.LLMReviewError) as ctx:
            module.extract_chat_content({"choices": [], "private": "provider detail"})
        self.assertIn("no choices", str(ctx.exception))
        self.assertNotIn("provider detail", str(ctx.exception))

        with self.assertRaisesRegex(module.LLMReviewError, "empty content"):
            module.extract_chat_content({"choices": [None]})

    def test_call_rejects_invalid_or_non_object_json(self):
        module = load_pr_review_module()
        invalid = Mock(status_code=200)
        invalid.json.side_effect = ValueError("invalid")
        with (
            patch.dict(module.os.environ, {"OPENAI_API_KEY": "test"}, clear=True),
            patch.object(module.requests, "post", return_value=invalid),
            self.assertRaisesRegex(module.LLMReviewError, "invalid JSON"),
        ):
            module.call_llm("diff", "default", "system")

        non_object = Mock(status_code=200)
        non_object.json.return_value = []
        with (
            patch.dict(module.os.environ, {"OPENAI_API_KEY": "test"}, clear=True),
            patch.object(module.requests, "post", return_value=non_object),
            self.assertRaisesRegex(module.LLMReviewError, "non-object JSON"),
        ):
            module.call_llm("diff", "default", "system")
