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

import unittest
from unittest.mock import MagicMock, patch

from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import (
    AiProfile,
    ScanRequest,
    ScanResponse,
)
from aisecurity.generated_openapi_client.models.metadata import Metadata
from aisecurity.generated_openapi_client.urllib3.exceptions import ApiException
from aisecurity.scan.inline.scan_executor import ScanExecutor
from aisecurity.scan.models.content import Content


class TestScanExecutor(unittest.TestCase):
    def setUp(self):
        self.scan_executor = ScanExecutor()

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_sync_request_success(self, mock_scan_api):
        mock_scan_api.scan_sync_request = MagicMock()
        mock_scan_api.scan_sync_request.return_value = ScanResponse(
            report_id="REP12345678910",
            scan_id="test_id",
            category="malign",
            action="block",
        )

        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile()
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        result = self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertIsInstance(result, ScanResponse)
        mock_scan_api.scan_sync_request.assert_called_once()

        call_args = mock_scan_api.scan_sync_request.call_args[1]["scan_request"]
        self.assertIsInstance(call_args, ScanRequest)
        self.assertEqual(len(call_args.contents), 1)
        self.assertEqual(call_args.contents[0].prompt, "Test prompt")
        self.assertEqual(call_args.contents[0].response, "Test response")
        self.assertEqual(call_args.ai_profile, ai_profile)
        self.assertEqual(call_args.tr_id, tr_id)
        self.assertEqual(call_args.metadata, metadata)

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_sync_request_success_for_only_prompt(self, mock_scan_api):
        mock_scan_api.scan_sync_request = MagicMock()
        mock_scan_api.scan_sync_request.return_value = ScanResponse(
            report_id="REP12345678910",
            scan_id="test_id",
            category="malign",
            action="block",
        )

        content = Content(prompt="Test prompt")
        ai_profile = AiProfile()
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        result = self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertIsInstance(result, ScanResponse)
        mock_scan_api.scan_sync_request.assert_called_once()

        call_args = mock_scan_api.scan_sync_request.call_args[1]["scan_request"]
        self.assertIsInstance(call_args, ScanRequest)
        self.assertEqual(len(call_args.contents), 1)
        self.assertEqual(call_args.contents[0].prompt, "Test prompt")
        self.assertEqual(call_args.ai_profile, ai_profile)
        self.assertEqual(call_args.tr_id, tr_id)
        self.assertEqual(call_args.metadata, metadata)

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_sync_request_success_for_only_response(self, mock_scan_api):
        mock_scan_api.scan_sync_request = MagicMock()
        mock_scan_api.scan_sync_request.return_value = ScanResponse(
            report_id="REP12345678910",
            scan_id="test_id",
            category="malign",
            action="block",
        )
        content = Content(response="Test response")
        ai_profile = AiProfile()
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        result = self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertIsInstance(result, ScanResponse)
        mock_scan_api.scan_sync_request.assert_called_once()

        call_args = mock_scan_api.scan_sync_request.call_args[1]["scan_request"]
        self.assertIsInstance(call_args, ScanRequest)
        self.assertEqual(len(call_args.contents), 1)
        self.assertEqual(call_args.contents[0].response, "Test response")
        self.assertEqual(call_args.ai_profile, ai_profile)
        self.assertEqual(call_args.tr_id, tr_id)
        self.assertEqual(call_args.metadata, metadata)

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.logger")
    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_sync_request_logs_error(self, mock_scan_api, mock_logger):
        mock_scan_api.scan_sync_request = MagicMock(side_effect=Exception("Test error"))

        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile()
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException):
            self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        mock_logger.error.assert_called_once()

    def test_singleton(self):
        another_executor = ScanExecutor()
        self.assertIs(self.scan_executor, another_executor)

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_async_request_forbidden_exception(self, mock_scan_api):
        mock_scan_api.scan_sync_request.side_effect = ApiException(status=403, reason="Forbidden")
        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)
        self.assertTrue("403" in str(context.exception))
        self.assertTrue("Forbidden" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_async_request_authorisation_exception(self, mock_scan_api):
        mock_scan_api.scan_sync_request.side_effect = ApiException(status=401, reason="Unauthorized")
        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)
        self.assertTrue("401" in str(context.exception))
        self.assertTrue("Unauthorized" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_async_request_connection_error(self, mock_scan_api):
        mock_scan_api.scan_sync_request.side_effect = ConnectionError("Network UnReachable")
        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("Network UnReachable" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_async_request_internal_server_exception(self, mock_scan_api):
        mock_scan_api.scan_sync_request.side_effect = ApiException(status=500, reason="Internal Server Error")
        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("500" in str(context.exception))
        self.assertTrue("Internal Server Error" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_async_request_timeout_error(self, mock_scan_api):
        mock_scan_api.scan_sync_request.side_effect = TimeoutError("Request timed out")
        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("Request timed out" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_async_request_type_error(self, mock_scan_api):
        mock_scan_api.scan_sync_request.side_effect = TypeError("Invalid Type")
        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("Invalid Type" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.scan_executor.ScanApiBase.scan_api")
    def test_async_request_value_error(self, mock_scan_api):
        mock_scan_api.scan_sync_request.side_effect = ValueError("Invalid Value")
        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "1234"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("Invalid Value" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
