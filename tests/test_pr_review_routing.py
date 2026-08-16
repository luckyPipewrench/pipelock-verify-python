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

    def test_workflow_delegates_model_defaults_to_python(self):
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("PR_REVIEW_MODEL_FAST: ${{ vars.PR_REVIEW_MODEL_FAST }}", workflow)
        self.assertIn("PR_REVIEW_MODEL_DEEP: ${{ vars.PR_REVIEW_MODEL_DEEP }}", workflow)
        self.assertIsNone(re.search(r"PR_REVIEW_MODEL_(?:FAST|DEEP): gpt-", workflow))

    def test_workflow_keeps_trusted_runner_and_owner_gate(self):
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("github.event.comment.user.login == 'luckyPipewrench'", workflow)
        self.assertIn("github.event.comment.author_association == 'OWNER'", workflow)
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("LITELLM_BASE_URL: ${{ secrets.LITELLM_BASE_URL }}", workflow)
        self.assertIn("LITELLM_API_KEY: ${{ secrets.LITELLM_API_KEY }}", workflow)
        self.assertIn("OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}", workflow)
        self.assertIn(
            "group: pr-review-${{ github.repository }}-${{ github.event.issue.number }}", workflow
        )
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("python -m unittest tests/test_pr_review_routing.py", workflow)

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
