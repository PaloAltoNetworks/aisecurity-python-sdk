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
    MAX_CONTENT_PROMPT_LENGTH,
    MAX_CONTENT_RESPONSE_LENGTH,
)
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.scan.models.content import Content


class TestContent(unittest.TestCase):
    def test_init_and_properties(self):
        content = Content(prompt="Test prompt", response="Test response")
        self.assertEqual(content.prompt, "Test prompt")
        self.assertEqual(content.response, "Test response")

    def test_length_constraints(self):
        with self.assertRaises(AISecSDKException):
            Content(prompt="A" * (MAX_CONTENT_PROMPT_LENGTH + 1))

        with self.assertRaises(AISecSDKException):
            Content(response="A" * (MAX_CONTENT_RESPONSE_LENGTH + 1))

    def test_to_json(self):
        content = Content(prompt="Test prompt", response="Test response")
        json_str = content.to_json()
        expected = json.dumps({"prompt": "Test prompt", "response": "Test response"})
        self.assertEqual(json_str, expected)

    def test_from_json(self):
        json_str = '{"prompt": "Test prompt", "response": "Test response"}'
        content = Content.from_json(json_str)
        self.assertEqual(content.prompt, "Test prompt")
        self.assertEqual(content.response, "Test response")

    def test_from_json_file(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
            json.dump({"prompt": "Test prompt", "response": "Test response"}, temp_file)

        content = Content.from_json_file(temp_file.name)
        self.assertEqual(content.prompt, "Test prompt")
        self.assertEqual(content.response, "Test response")

    def test_len(self):
        content = Content(prompt="Test prompt", response="Test response")
        self.assertEqual(len(content), len("Test prompt") + len("Test response"))

    def test_str(self):
        content = Content(prompt="Test prompt", response="Test response")
        self.assertEqual(str(content), "Content(prompt=Test prompt, response=Test response)")

    def test_invalid_content(self):
        with self.assertRaises(AISecSDKException) as context:
            Content(prompt=None, response=None)
        self.assertTrue("Must provide Prompt/Response Content" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)

        with self.assertRaises(AISecSDKException) as context:
            Content(prompt="", response="")

        self.assertTrue("Must provide Prompt/Response Content" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)

    # TODO need to add test for exceptions


if __name__ == "__main__":
    unittest.main()
