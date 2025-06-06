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

import pytest

from aisecurity.exceptions import AISecSDKException, ErrorType


def test_error_type_enum():
    assert isinstance(ErrorType.SERVER_SIDE_ERROR, Enum)
    assert ErrorType.SERVER_SIDE_ERROR.value == "AISEC_SERVER_SIDE_ERROR"
    assert ErrorType.CLIENT_SIDE_ERROR.value == "AISEC_CLIENT_SIDE_ERROR"
    assert ErrorType.USER_REQUEST_PAYLOAD_ERROR.value == "AISEC_USER_REQUEST_PAYLOAD_ERROR"
    assert ErrorType.MISSING_VARIABLE.value == "AISEC_MISSING_VARIABLE"


def test_aisec_sdk_exception_init():
    exc = AISecSDKException("Test message", ErrorType.SERVER_SIDE_ERROR)
    assert exc.message == "Test message"
    assert exc.error_type == ErrorType.SERVER_SIDE_ERROR


def test_aisec_sdk_exception_str():
    exc = AISecSDKException("Test message", ErrorType.CLIENT_SIDE_ERROR)
    assert str(exc) == "AISEC_CLIENT_SIDE_ERROR:Test message"


def test_aisec_sdk_exception_default_values():
    exc = AISecSDKException()
    assert exc.message == ""
    assert exc.error_type is None


@pytest.mark.parametrize(
    "message,error_type,expected_str",
    [
        (
            "Payload error occurred",
            ErrorType.USER_REQUEST_PAYLOAD_ERROR,
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:Payload error occurred",
        ),
        (
            "Missing environment variable",
            ErrorType.MISSING_VARIABLE,
            "AISEC_MISSING_VARIABLE:Missing environment variable",
        ),
        (
            "Server error",
            ErrorType.SERVER_SIDE_ERROR,
            "AISEC_SERVER_SIDE_ERROR:Server error",
        ),
    ],
)
def test_aisec_sdk_exception_parameterized(message, error_type, expected_str):
    exc = AISecSDKException(message, error_type)
    assert str(exc) == expected_str
