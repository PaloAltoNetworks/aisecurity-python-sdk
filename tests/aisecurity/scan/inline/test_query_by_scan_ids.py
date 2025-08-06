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
import uuid
from unittest.mock import patch

from aisecurity.constants.base import MAX_NUMBER_OF_SCAN_IDS, MAX_SCAN_ID_STR_LENGTH
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import ScanIdResult
from aisecurity.generated_openapi_client.urllib3.exceptions import ApiException
from aisecurity.scan.inline.query_by_scan_ids import QueryByScanIds


class TestQueryByScanIds(unittest.TestCase):
    def setUp(self):
        self.query_by_scan_ids = QueryByScanIds()

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_success(self, mock_scan_results_api):
        mock_scan_results_api.return_value = [ScanIdResult()]
        scan_ids = [str(uuid.uuid4()) for _ in range(3)]
        results = self.query_by_scan_ids.get_scan_results(scan_ids)

        self.assertIsInstance(results, list)
        self.assertIsInstance(results[0], ScanIdResult)
        mock_scan_results_api.assert_called_once_with(scan_ids=scan_ids)

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_empty_list(self, mock_get_scan_results_by_scan_ids_api):
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results([])

        self.assertIn("At least one scan ID must be provided", str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_exceed_max_ids(self, mock_get_scan_results_by_scan_ids_api):
        scan_ids = [str(uuid.uuid4())] * (MAX_NUMBER_OF_SCAN_IDS + 1)
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)

        self.assertIn(
            f"Number of scan IDs exceeds the maximum allowed ({MAX_NUMBER_OF_SCAN_IDS})",
            str(context.exception),
        )
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_id_too_long(self, mock_get_scan_results_by_scan_ids_api):
        scan_ids = ["a" * (MAX_SCAN_ID_STR_LENGTH + 1)]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertIn("exceeds the maximum allowed length", str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_invalid_scan_objects(self, mock_get_scan_results_by_scan_ids_api):
        scan_ids = [str(uuid.uuid4()), str(uuid.uuid4()), None]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertIn("Scan Id can't be None or empty", str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

        scan_ids = ["", str(uuid.uuid4())]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertIn("Scan Id can't be None or empty", str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_invalid_scan_id_format(self, mock_get_scan_results_by_scan_ids_api):
        scan_ids = ["a"]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertIn("Scan ID format must be in UUID format", str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_unexpected_error(self, mock_scan_results_api):
        mock_scan_results_api.side_effect = Exception("Unexpected Error")
        scan_ids = [str(uuid.uuid4())]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertTrue("Unexpected Error" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_request_client_invalid_type_error(self, mock_scan_results_api):
        mock_scan_results_api.side_effect = TypeError("Invalid type")

        scan_ids = [str(uuid.uuid4())]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertTrue("Invalid type" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_request_client_invalid_value_error(self, mock_scan_results_api):
        mock_scan_results_api.side_effect = ValueError("Invalid value")

        scan_ids = [str(uuid.uuid4())]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        print(str(context.exception))
        self.assertTrue("Invalid value" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_request_client_timeout_error(self, mock_scan_results_api):
        mock_scan_results_api.side_effect = TimeoutError("Request timed out")

        scan_ids = [str(uuid.uuid4())]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        print(str(context.exception))
        self.assertTrue("Request timed out" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_network_error(self, mock_scan_results_api):
        mock_scan_results_api.side_effect = ConnectionError("Network unreachable")

        scan_ids = [str(uuid.uuid4())]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        print(str(context.exception))
        self.assertTrue("Network unreachable" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_internal_server_error(self, mock_scan_results_api):
        mock_scan_results_api.side_effect = ApiException(status=500, reason="Internal Server Error")

        scan_ids = [str(uuid.uuid4())]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertTrue("Internal Server Error" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_forbidden_exception_error(self, mock_scan_results_api):
        mock_scan_results_api.side_effect = ApiException(status=403, reason="Forbidden")

        scan_ids = [str(uuid.uuid4())]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertTrue("Forbidden" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids")
    def test_get_scan_results_unauthorized_exception_error(self, mock_scan_results_api):
        mock_scan_results_api.side_effect = ApiException(status=403, reason="Unauthorized")

        scan_ids = [str(uuid.uuid4())]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertTrue("Unauthorized" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)

    def test_singleton(self):
        another_instance = QueryByScanIds()
        self.assertIs(self.query_by_scan_ids, another_instance)


if __name__ == "__main__":
    unittest.main()
