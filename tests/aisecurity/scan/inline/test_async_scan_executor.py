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
from datetime import datetime
from unittest.mock import MagicMock, patch

from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import AsyncScanObject, AsyncScanResponse
from aisecurity.generated_openapi_client.urllib3.exceptions import ApiException
from aisecurity.scan.inline.async_scan_executor import AsyncScanExecutor


class TestAsyncScanExecutor(unittest.TestCase):
    def setUp(self):
        self.async_scan_executor = AsyncScanExecutor()

    @patch("aisecurity.scan.inline.async_scan_executor.ScanApiBase.scan_api")
    def test_async_request_success(self, mock_scan_api):
        mock_scan_api.scan_async_request = MagicMock(
            return_value=AsyncScanResponse(
                received=datetime(2024, 11, 21, 20, 21, 11, 855863),
                scan_id="test_id",
            )
        )

        async_scan_objects = MagicMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]
        result = self.async_scan_executor.async_request(scan_objects)

        self.assertIsInstance(result, AsyncScanResponse)
        mock_scan_api.scan_async_request.assert_called_once_with(async_scan_object=scan_objects)

    @patch("aisecurity.scan.inline.async_scan_executor.ScanApiBase.logger")
    @patch("aisecurity.scan.inline.async_scan_executor.ScanApiBase.scan_api")
    def test_async_request_logs_error(self, mock_scan_api, mock_logger):
        mock_scan_api.scan_async_request = MagicMock(side_effect=Exception("Test error"))

        scan_objects = [MagicMock(spec=AsyncScanObject)]
        with self.assertRaises(Exception):
            self.async_scan_executor.async_request(scan_objects)

        mock_logger.error.assert_called_once()

    def test_singleton(self):
        another_executor = AsyncScanExecutor()
        self.assertIs(self.async_scan_executor, another_executor)

    @patch("aisecurity.scan.inline.async_scan_executor.ScanApiBase.scan_api")
    def test_async_request_forbidden_exception(self, mock_scan_api):
        mock_scan_api.scan_async_request.side_effect = ApiException(status=403, reason="Forbidden")
        async_scan_objects = MagicMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            self.async_scan_executor.async_request(scan_objects)
        print(str(context.exception))
        self.assertTrue("403" in str(context.exception))
        self.assertTrue("Forbidden" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.async_scan_executor.ScanApiBase.scan_api")
    def test_async_request_unauthorised_exception(self, mock_scan_api):
        mock_scan_api.scan_async_request.side_effect = ApiException(status=401, reason="unauthorised")
        async_scan_objects = MagicMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            self.async_scan_executor.async_request(scan_objects)
        print(str(context.exception))
        self.assertTrue("401" in str(context.exception))
        self.assertTrue("unauthorised" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.async_scan_executor.ScanApiBase.scan_api")
    def test_async_request_connection_error(self, mock_scan_api):
        mock_scan_api.scan_async_request.side_effect = ConnectionError("Network Unreachable")
        async_scan_objects = MagicMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("Network Unreachable" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.async_scan_executor.ScanApiBase.scan_api")
    def test_async_request_internal_server_exception(self, mock_scan_api):
        mock_scan_api.scan_async_request.side_effect = ApiException(status=500, reason="Internal Server Error")
        async_scan_objects = MagicMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("500" in str(context.exception))
        self.assertTrue("Internal Server Error" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.async_scan_executor.ScanApiBase.scan_api")
    def test_async_request_timeout_error(self, mock_scan_api):
        mock_scan_api.scan_async_request.side_effect = TimeoutError("Request timed out")
        async_scan_objects = MagicMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("Request timed out" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.async_scan_executor.ScanApiBase.scan_api")
    def test_async_request_value_error(self, mock_scan_api):
        mock_scan_api.scan_async_request.side_effect = ValueError("Invalid Value")
        async_scan_objects = MagicMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("Invalid Value" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()

    @patch("aisecurity.scan.inline.async_scan_executor.ScanApiBase.scan_api")
    def test_async_request_type_error(self, mock_scan_api):
        mock_scan_api.scan_async_request.side_effect = TypeError("Invalid Type")
        async_scan_objects = MagicMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("Invalid Type" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)
        mock_scan_api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
