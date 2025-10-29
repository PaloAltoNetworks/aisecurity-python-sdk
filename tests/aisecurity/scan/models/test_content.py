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
from unittest.mock import Mock

from aisecurity.constants.base import (
    MAX_CONTENT_CONTEXT_LENGTH,
    MAX_CONTENT_PROMPT_LENGTH,
    MAX_CONTENT_RESPONSE_LENGTH,
)
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.scan.models.content import Content
from aisecurity.generated_openapi_client.models.tool_event import ToolEvent


class TestContent(unittest.TestCase):
    def test_init_and_properties(self):
        tool_event = ToolEvent()
        content = Content(
            prompt="Test prompt",
            response="Test response",
            context="Test context",
            code_prompt="Test code prompt",
            code_response="Test code response",
            tool_event=tool_event,
        )
        self.assertEqual(content.prompt, "Test prompt")
        self.assertEqual(content.response, "Test response")
        self.assertEqual(content.context, "Test context")
        self.assertEqual(content.code_prompt, "Test code prompt")
        self.assertEqual(content.code_response, "Test code response")
        self.assertIsInstance(content.tool_event, ToolEvent)

    def test_type_validation(self):
        # Test prompt type validation
        with self.assertRaises(AISecSDKException) as context:
            Content(prompt=123)
        self.assertEqual(context.exception.error_type, ErrorType.USER_REQUEST_PAYLOAD_ERROR)
        self.assertIn("Prompt must be of type str", str(context.exception))

        # Test response type validation
        with self.assertRaises(AISecSDKException) as context:
            Content(response=123)
        self.assertEqual(context.exception.error_type, ErrorType.USER_REQUEST_PAYLOAD_ERROR)
        self.assertIn("Response must be of type str", str(context.exception))

        # Test context type validation
        with self.assertRaises(AISecSDKException) as context:
            Content(prompt="Test", context=123)
        self.assertEqual(context.exception.error_type, ErrorType.USER_REQUEST_PAYLOAD_ERROR)
        self.assertIn("Context must be of type str", str(context.exception))

        # Test code_prompt type validation
        with self.assertRaises(AISecSDKException) as context:
            Content(code_prompt=123)
        self.assertEqual(context.exception.error_type, ErrorType.USER_REQUEST_PAYLOAD_ERROR)
        self.assertIn("Code prompt must be of type str", str(context.exception))

        # Test code_response type validation
        with self.assertRaises(AISecSDKException) as context:
            Content(code_response=123)
        self.assertEqual(context.exception.error_type, ErrorType.USER_REQUEST_PAYLOAD_ERROR)
        self.assertIn("Code response must be of type str", str(context.exception))

        # Test with list type
        with self.assertRaises(AISecSDKException) as context:
            Content(prompt=["test"])
        self.assertEqual(context.exception.error_type, ErrorType.USER_REQUEST_PAYLOAD_ERROR)
        self.assertIn("Prompt must be of type str", str(context.exception))

        # Test with dict type
        with self.assertRaises(AISecSDKException) as context:
            Content(response={"key": "value"})
        self.assertEqual(context.exception.error_type, ErrorType.USER_REQUEST_PAYLOAD_ERROR)
        self.assertIn("Response must be of type str", str(context.exception))

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

    def test_tool_event_validation(self):
        # Test valid ToolEvent
        tool_event = ToolEvent()
        content = Content(tool_event=tool_event)
        self.assertIsInstance(content.tool_event, ToolEvent)

        # Test invalid tool_event type
        with self.assertRaises(AISecSDKException) as context:
            Content(tool_event="invalid_type")
        self.assertEqual(context.exception.error_type, ErrorType.USER_REQUEST_PAYLOAD_ERROR)
        self.assertIn("tool_event must be an instance of ToolEvent", str(context.exception))

    def test_to_json(self):
        tool_event = ToolEvent()
        content = Content(
            prompt="Test prompt",
            response="Test response",
            context="Test context",
            code_prompt="Test code prompt",
            code_response="Test code response",
            tool_event=tool_event,
        )
        json_str = content.to_json()
        expected = json.dumps({
            "prompt": "Test prompt",
            "response": "Test response",
            "context": "Test context",
            "code_prompt": "Test code prompt",
            "code_response": "Test code response",
            "tool_event": tool_event.to_dict(),
        })
        self.assertEqual(json_str, expected)

    def test_to_json_with_none_tool_event(self):
        content = Content(prompt="Test prompt")
        json_str = content.to_json()
        expected = json.dumps({
            "prompt": "Test prompt",
            "response": None,
            "context": None,
            "code_prompt": None,
            "code_response": None,
            "tool_event": None,
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
        self.assertIsNone(content.tool_event)

    def test_from_json_with_tool_event(self):
        # Mock ToolEvent.from_dict
        mock_tool_event = Mock(spec=ToolEvent)
        ToolEvent.from_dict = Mock(return_value=mock_tool_event)

        json_str = """
        {
            "prompt": "Test prompt",
            "tool_event": {"input": "test_input", "output": "test_output"}
        }
        """
        content = Content.from_json(json_str)
        self.assertEqual(content.prompt, "Test prompt")
        self.assertEqual(content.tool_event, mock_tool_event)
        ToolEvent.from_dict.assert_called_once_with({"input": "test_input", "output": "test_output"})

    def test_from_json_with_none_input(self):
        # Test that from_json returns None when json_str is None
        content = Content.from_json(None)
        self.assertIsNone(content)

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

    def test_from_json_file_with_none_file_path(self):
        # Test that from_json_file raises exception when file_path is None
        with self.assertRaises(AISecSDKException) as context:
            Content.from_json_file(None)
        self.assertEqual(context.exception.error_type, ErrorType.USER_REQUEST_PAYLOAD_ERROR)
        self.assertIn("File path cannot be None", str(context.exception))

    def test_from_json_file_with_non_existent_file(self):
        # Test that from_json_file raises exception when file does not exist
        non_existent_path = "/tmp/non_existent_file_12345.json"
        with self.assertRaises(AISecSDKException) as context:
            Content.from_json_file(non_existent_path)
        self.assertEqual(context.exception.error_type, ErrorType.USER_REQUEST_PAYLOAD_ERROR)
        self.assertIn("File not found", str(context.exception))

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

    def test_len_with_tool_event(self):
        # Mock ToolEvent with input and output
        tool_event = Mock(spec=ToolEvent)
        tool_event.input = "test input"
        tool_event.output = "test output"

        content = Content(prompt="Test prompt", tool_event=tool_event)
        expected_length = len("Test prompt") + len("test input") + len("test output")
        self.assertEqual(len(content), expected_length)

    def test_len_with_tool_event_none_fields(self):
        # Mock ToolEvent with None input and output
        tool_event = Mock(spec=ToolEvent)
        tool_event.input = None
        tool_event.output = None

        content = Content(prompt="Test prompt", tool_event=tool_event)
        expected_length = len("Test prompt")
        self.assertEqual(len(content), expected_length)

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
            + "code_prompt=Test code prompt, code_response=Test code response, tool_event=None)",
        )

    def test_invalid_content(self):
        with self.assertRaises(AISecSDKException) as context:
            Content(prompt=None, response=None, context=None, code_prompt=None, code_response=None, tool_event=None)
        self.assertIn(
            "content validation failed: at least one of Prompt, Response, CodePrompt, CodeResponse, or ToolEvent must be provided",
            str(context.exception),
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
        self.assertIsNone(content.tool_event)

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

        # Valid with only tool_event
        tool_event = ToolEvent()
        content = Content(tool_event=tool_event)
        self.assertEqual(content.tool_event, tool_event)
        self.assertIsNone(content.prompt)

        # Empty strings should not be valid
        with self.assertRaises(AISecSDKException) as context:
            Content(prompt="", response="", code_prompt="", code_response="", tool_event=None)
        self.assertIn(
            "content validation failed: at least one of Prompt, Response, CodePrompt, CodeResponse, or ToolEvent must be provided",
            str(context.exception),
        )

        with self.assertRaises(AISecSDKException) as context:
            Content(context="ABC")
        self.assertIn(
            "content validation failed: at least one of Prompt, Response, CodePrompt, CodeResponse, or ToolEvent must be provided",
            str(context.exception),
        )

    def test_code_prompt_response_only(self):
        # Test that a Content object can be created with only code_prompt and code_response
        content = Content(code_prompt="Test code prompt", code_response="Test code response")
        self.assertIsNone(content.prompt)
        self.assertIsNone(content.response)
        self.assertEqual(content.code_prompt, "Test code prompt")
        self.assertEqual(content.code_response, "Test code response")
        self.assertIsNone(content.tool_event)


if __name__ == "__main__":
    unittest.main()
