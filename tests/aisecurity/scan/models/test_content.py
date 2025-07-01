# Copyright (c) 2025, Palo Alto Networks
#
# Licensed under the Polyform Internal Use License 1.0.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
#
# https://polyformproject.org/licenses/internal-use/1.0.0
# (or)
# https://github.com/polyformproject/polyform-licenses/blob/76a278c4/PolyForm-Internal-Use-1.0.0.md
#
# As far as the law allows, the software comes as is, without any warranty
# or condition, and the licensor will not be liable to you for any damages
# arising out of these terms or the use or nature of the software, under
# any kind of legal claim.

import json
import tempfile
import unittest

from aisecurity.constants.base import (
    MAX_CONTENT_CONTEXT_LENGTH,
    MAX_CONTENT_PROMPT_LENGTH,
    MAX_CONTENT_RESPONSE_LENGTH,
)
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.scan.models.content import Content


class TestContent(unittest.TestCase):
    def test_init_and_properties(self):
        content = Content(
            prompt="Test prompt",
            response="Test response",
            context="Test context",
            code_prompt="Test code prompt",
            code_response="Test code response",
        )
        self.assertEqual(content.prompt, "Test prompt")
        self.assertEqual(content.response, "Test response")
        self.assertEqual(content.context, "Test context")
        self.assertEqual(content.code_prompt, "Test code prompt")
        self.assertEqual(content.code_response, "Test code response")

    def test_length_constraints(self):
        with self.assertRaises(AISecSDKException):
            Content(prompt="A" * (MAX_CONTENT_PROMPT_LENGTH + 1))

        with self.assertRaises(AISecSDKException):
            Content(response="A" * (MAX_CONTENT_RESPONSE_LENGTH + 1))

        with self.assertRaises(AISecSDKException):
            Content(prompt="Test", context="A" * (MAX_CONTENT_CONTEXT_LENGTH + 1))

        with self.assertRaises(AISecSDKException):
            Content(code_prompt="A" * (MAX_CONTENT_PROMPT_LENGTH + 1))

        with self.assertRaises(AISecSDKException):
            Content(code_response="A" * (MAX_CONTENT_RESPONSE_LENGTH + 1))

    def test_to_json(self):
        content = Content(
            prompt="Test prompt",
            response="Test response",
            context="Test context",
            code_prompt="Test code prompt",
            code_response="Test code response",
        )
        json_str = content.to_json()
        expected = json.dumps({
            "prompt": "Test prompt",
            "response": "Test response",
            "context": "Test context",
            "code_prompt": "Test code prompt",
            "code_response": "Test code response",
        })
        self.assertEqual(json_str, expected)

    def test_from_json(self):
        json_str = """
        {
            "prompt": "Test prompt",
            "response": "Test response",
            "context": "Test context",
            "code_prompt": "Test code prompt",
            "code_response": "Test code response"
        }
        """
        content = Content.from_json(json_str)
        self.assertEqual(content.prompt, "Test prompt")
        self.assertEqual(content.response, "Test response")
        self.assertEqual(content.context, "Test context")
        self.assertEqual(content.code_prompt, "Test code prompt")
        self.assertEqual(content.code_response, "Test code response")

    def test_from_json_file(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
            json.dump(
                {
                    "prompt": "Test prompt",
                    "response": "Test response",
                    "context": "Test context",
                    "code_prompt": "Test code prompt",
                    "code_response": "Test code response",
                },
                temp_file,
            )

        content = Content.from_json_file(temp_file.name)
        self.assertEqual(content.prompt, "Test prompt")
        self.assertEqual(content.response, "Test response")
        self.assertEqual(content.context, "Test context")
        self.assertEqual(content.code_prompt, "Test code prompt")
        self.assertEqual(content.code_response, "Test code response")

    def test_len(self):
        content = Content(
            prompt="Test prompt",
            response="Test response",
            context="Test context",
            code_prompt="Test code prompt",
            code_response="Test code response",
        )
        self.assertEqual(
            len(content),
            len("Test prompt")
            + len("Test response")
            + len("Test context")
            + len("Test code prompt")
            + len("Test code response"),
        )

    def test_str(self):
        content = Content(
            prompt="Test prompt",
            response="Test response",
            context="Test context",
            code_prompt="Test code prompt",
            code_response="Test code response",
        )
        self.assertEqual(
            str(content),
            "Content(prompt=Test prompt, response=Test response, context=Test context, "
            + "code_prompt=Test code prompt, code_response=Test code response))",
        )

    def test_invalid_content(self):
        with self.assertRaises(AISecSDKException) as context:
            Content(
                prompt=None,
                response=None,
                context=None,
                code_prompt=None,
                code_response=None,
            )
        self.assertTrue(
            "Must provide Prompt/Response Content or Code Prompt/Response Content" in str(context.exception)
        )
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)

    def test_optional_context(self):
        # Context is optional
        content = Content(prompt="Test prompt", response="Test response")
        self.assertEqual(content.prompt, "Test prompt")
        self.assertEqual(content.response, "Test response")
        self.assertIsNone(content.context)
        self.assertIsNone(content.code_prompt)
        self.assertIsNone(content.code_response)

    def test_only_prompt_or_response_required(self):
        # Valid with only prompt
        content = Content(prompt="Test prompt")
        self.assertEqual(content.prompt, "Test prompt")
        self.assertIsNone(content.response)

        # Valid with only response
        content = Content(response="Test response")
        self.assertIsNone(content.prompt)
        self.assertEqual(content.response, "Test response")

        # Valid with only code prompt
        content = Content(code_prompt="Test code prompt")
        self.assertEqual(content.code_prompt, "Test code prompt")
        self.assertIsNone(content.prompt)

        # Valid with only code response
        content = Content(code_response="Test code response")
        self.assertEqual(content.code_response, "Test code response")
        self.assertIsNone(content.response)

        # Empty strings should not be valid
        with self.assertRaises(AISecSDKException) as context:
            Content(prompt="", response="", code_prompt="", code_response="")
        self.assertTrue(
            "Must provide Prompt/Response Content or Code Prompt/Response Content" in str(context.exception)
        )

        with self.assertRaises(AISecSDKException) as context:
            Content(context="ABC")
        self.assertTrue(
            "Must provide Prompt/Response Content or Code Prompt/Response Content" in str(context.exception)
        )

    def test_code_prompt_response_only(self):
        # Test that a Content object can be created with only code_prompt and code_response
        content = Content(code_prompt="Test code prompt", code_response="Test code response")
        self.assertIsNone(content.prompt)
        self.assertIsNone(content.response)
        self.assertEqual(content.code_prompt, "Test code prompt")
        self.assertEqual(content.code_response, "Test code response")


if __name__ == "__main__":
    unittest.main()
