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

from aisecurity.constants.base import (
    MAX_CONTENT_PROMPT_LENGTH,
    MAX_CONTENT_RESPONSE_LENGTH,
)
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.logger import BaseLogger


class Content(BaseLogger):
    def __init__(self, prompt=None, response=None):
        super().__init__()
        self._prompt = None
        self._response = None
        self.prompt = prompt  # This will trigger the setter with the length check
        self.response = response  # This will trigger the setter with the length check

        if not self.prompt and not self.response:
            error_msg = "Must provide Prompt/Response Content"
            raise AISecSDKException(
                error_msg,
                ErrorType.USER_REQUEST_PAYLOAD_ERROR,
            )

    @property
    def prompt(self):
        return self._prompt

    @prompt.setter
    def prompt(self, value):
        if value is not None and len(value) > MAX_CONTENT_PROMPT_LENGTH:
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
        if value is not None and len(value) > MAX_CONTENT_RESPONSE_LENGTH:
            raise AISecSDKException(
                f"Response length exceeds maximum allowed length of {MAX_CONTENT_RESPONSE_LENGTH} characters",
                ErrorType.USER_REQUEST_PAYLOAD_ERROR,
            )
        self._response = value

    def to_json(self):
        return json.dumps({"prompt": self._prompt, "response": self._response})

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls(prompt=data.get("prompt"), response=data.get("response"))

    @classmethod
    def from_json_file(cls, file_path):
        with open(file_path) as json_file:
            data = json.load(json_file)
        return cls(prompt=data.get("prompt"), response=data.get("response"))

    def __len__(self):
        return len(self._prompt or "") + len(self._response or "")

    def __str__(self):
        return f"Content(prompt={self._prompt}, response={self._response})"
