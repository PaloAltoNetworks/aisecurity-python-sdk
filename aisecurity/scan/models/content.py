# Copyright (c) 2025, Palo Alto Networks

# Licensed under the Polyform Internal Use License 1.0.0 (the "License");
# you may not use this file except in compliance with the License.

# You may obtain a copy of the License at:

# https://polyformproject.org/licenses/internal-use/1.0.0
# (or)
# https://github.com/polyformproject/polyform-licenses/blob/76a278c4/PolyForm-Internal-Use-1.0.0.md

# As far as the law allows, the software comes as is, without any warranty
# or condition, and the licensor will not be liable to you for any damages
# arising out of these terms or the use or nature of the software, under
# any kind of legal claim.

import json
from aisecurity.constants.base import (
    MAX_CONTENT_CONTEXT_LENGTH,
    MAX_CONTENT_PROMPT_LENGTH,
    MAX_CONTENT_RESPONSE_LENGTH,
)
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.logger import BaseLogger
from aisecurity.generated_openapi_client.models.tool_event import ToolEvent


class Content(BaseLogger):
    def __init__(self, prompt=None, response=None, context=None, code_prompt=None, code_response=None, tool_event=None):
        super().__init__()
        self._prompt = None
        self._response = None
        self._context = None
        self._code_prompt = None
        self._code_response = None
        self._tool_event = None
        self.prompt = prompt  # This will trigger the setter with the length check
        self.response = response  # This will trigger the setter with the length check
        self.context = context
        self.code_prompt = code_prompt
        self.code_response = code_response
        self.tool_event = tool_event

        if (
            not self.prompt
            and not self.response
            and not self.code_prompt
            and not self.code_response
            and not self.tool_event
        ):
            error_msg = "content validation failed: at least one of Prompt, Response, CodePrompt, CodeResponse, or ToolEvent must be provided"
            raise AISecSDKException(
                error_msg,
                ErrorType.USER_REQUEST_PAYLOAD_ERROR,
            )

    @property
    def prompt(self):
        return self._prompt

    @prompt.setter
    def prompt(self, value):
        if value is not None:
            if not isinstance(value, str):
                raise AISecSDKException(
                    "Prompt must be of type str",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
            if len(value) > MAX_CONTENT_PROMPT_LENGTH:
                raise AISecSDKException(
                    f"Prompt length exceeds maximum allowed length of {MAX_CONTENT_PROMPT_LENGTH} characters",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
        self._prompt = value

    @property
    def response(self):
        return self._response

    @response.setter
    def response(self, value):
        if value is not None:
            if not isinstance(value, str):
                raise AISecSDKException(
                    "Response must be of type str",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
            if len(value) > MAX_CONTENT_RESPONSE_LENGTH:
                raise AISecSDKException(
                    f"Response length exceeds maximum allowed length of {MAX_CONTENT_RESPONSE_LENGTH} characters",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
        self._response = value

    @property
    def context(self):
        return self._context

    @context.setter
    def context(self, value):
        if value is not None:
            if not isinstance(value, str):
                raise AISecSDKException(
                    "Context must be of type str",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
            if len(value) > MAX_CONTENT_CONTEXT_LENGTH:
                raise AISecSDKException(
                    f"context length exceeds maximum allowed length of {MAX_CONTENT_CONTEXT_LENGTH} characters",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
        self._context = value

    @property
    def code_prompt(self):
        return self._code_prompt

    @code_prompt.setter
    def code_prompt(self, value):
        if value is not None:
            if not isinstance(value, str):
                raise AISecSDKException(
                    "Code prompt must be of type str",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
            if len(value) > MAX_CONTENT_PROMPT_LENGTH:
                raise AISecSDKException(
                    f"Code prompt length exceeds maximum allowed length of {MAX_CONTENT_PROMPT_LENGTH} characters",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
        self._code_prompt = value

    @property
    def code_response(self):
        return self._code_response

    @code_response.setter
    def code_response(self, value):
        if value is not None:
            if not isinstance(value, str):
                raise AISecSDKException(
                    "Code response must be of type str",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
            if len(value) > MAX_CONTENT_RESPONSE_LENGTH:
                raise AISecSDKException(
                    f"Code response length exceeds maximum allowed length of {MAX_CONTENT_RESPONSE_LENGTH} characters",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
        self._code_response = value

    @property
    def tool_event(self):
        return self._tool_event

    @tool_event.setter
    def tool_event(self, value):
        if value is not None and not isinstance(value, ToolEvent):
            raise AISecSDKException(
                "tool_event must be an instance of ToolEvent",
                ErrorType.USER_REQUEST_PAYLOAD_ERROR,
            )
        self._tool_event = value

    def to_json(self):
        tool_event_dict = None
        if self._tool_event is not None:
            tool_event_dict = self._tool_event.to_dict()

        return json.dumps({
            "prompt": self._prompt,
            "response": self._response,
            "context": self._context,
            "code_prompt": self._code_prompt,
            "code_response": self._code_response,
            "tool_event": tool_event_dict,
        })

    @classmethod
    def from_json(cls, json_str):
        if json_str is None:
            return None

        data = json.loads(json_str)
        tool_event = None
        if data.get("tool_event"):
            tool_event = ToolEvent.from_dict(data.get("tool_event"))

        return cls(
            prompt=data.get("prompt"),
            response=data.get("response"),
            context=data.get("context"),
            code_prompt=data.get("code_prompt"),
            code_response=data.get("code_response"),
            tool_event=tool_event,
        )

    @classmethod
    def from_json_file(cls, file_path):
        if file_path is None:
            raise AISecSDKException(
                "File path cannot be None",
                ErrorType.USER_REQUEST_PAYLOAD_ERROR,
            )

        try:
            with open(file_path) as json_file:
                data = json.load(json_file)
        except FileNotFoundError:
            raise AISecSDKException(
                f"File not found: {file_path}",
                ErrorType.USER_REQUEST_PAYLOAD_ERROR,
            )
        except (IOError, OSError) as e:
            raise AISecSDKException(
                f"Error reading file: {str(e)}",
                ErrorType.USER_REQUEST_PAYLOAD_ERROR,
            )

        tool_event = None
        if data.get("tool_event"):
            tool_event = ToolEvent.from_dict(data.get("tool_event"))

        return cls(
            prompt=data.get("prompt"),
            response=data.get("response"),
            context=data.get("context"),
            code_prompt=data.get("code_prompt"),
            code_response=data.get("code_response"),
            tool_event=tool_event,
        )

    def __len__(self):
        tool_event_length = 0
        if self._tool_event is not None:
            # Calculate length based on ToolEvent's input and output fields
            tool_event_length = len(self._tool_event.input or "") + len(self._tool_event.output or "")

        return (
            len(self._prompt or "")
            + len(self._response or "")
            + len(self._context or "")
            + len(self._code_prompt or "")
            + len(self._code_response or "")
            + tool_event_length
        )

    def __str__(self):
        return f"Content(prompt={self._prompt}, response={self._response}, context={self._context}, code_prompt={self._code_prompt}, code_response={self._code_response}, tool_event={self._tool_event})"
