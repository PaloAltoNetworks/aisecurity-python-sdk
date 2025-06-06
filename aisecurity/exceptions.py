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

from enum import Enum
from typing import Optional


class ErrorType(Enum):
    """Enum defining error type codes for AISecSDK exceptions.

    These error types are used to categorize different errors that can occur
    within the SDK and are included in exception messages.
    """

    SERVER_SIDE_ERROR = "AISEC_SERVER_SIDE_ERROR"
    CLIENT_SIDE_ERROR = "AISEC_CLIENT_SIDE_ERROR"
    USER_REQUEST_PAYLOAD_ERROR = "AISEC_USER_REQUEST_PAYLOAD_ERROR"
    MISSING_VARIABLE = "AISEC_MISSING_VARIABLE"
    AISEC_SDK_ERROR = "AISEC_SDK_ERROR"


class AISecSDKException(Exception):
    """Base exception class for SDK-related exceptions."""

    def __init__(self, message: str = "", error_type: Optional[ErrorType] = None) -> None:
        self.message = message
        self.error_type = error_type

    def __str__(self) -> str:
        if self.error_type:
            return f"{self.error_type.value}:{self.message}"
        return f"{self.message}"
