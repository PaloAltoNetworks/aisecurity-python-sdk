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
from unittest.mock import patch

from aisecurity.constants.base import MAX_NUMBER_OF_REPORT_IDS, MAX_REPORT_ID_STR_LENGTH
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import ThreatScanReportObject
from aisecurity.generated_openapi_client.urllib3.exceptions import ApiException
from aisecurity.scan.inline.query_by_report_ids import QueryByReportIds


class TestQueryByReportIds(unittest.TestCase):
    @patch("aisecurity.scan.inline.base.ApiBase.create_api_client")
    def setUp(self, mock_api_base):
        self.query_by_report_ids = QueryByReportIds()

    @patch("aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports")
    def test_get_threat_objects_success(self, mock_scan_reports_api):
        mock_scan_reports_api.return_value = [ThreatScanReportObject()]
        report_ids = ["report_id_1", "report_id_2"]
        results = self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertIsInstance(results, list)
        self.assertIsInstance(results[0], ThreatScanReportObject)
        mock_scan_reports_api.assert_called_once_with(report_ids=report_ids)

    @patch(
        "aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
    )
    def test_invalid_report_id_length(self, mock_get_threat_scan_reports_api):
        invalid_report_id = "a" * (MAX_REPORT_ID_STR_LENGTH + 1)
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects([invalid_report_id])

        self.assertTrue(f"Report ID '{invalid_report_id}' exceeds the maximum allowed length" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_not_called()

    @patch(
        "aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
    )
    def test_get_threat_objects_empty_list(self, mock_get_threat_scan_reports_api):
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects([])

        self.assertTrue("At least one report ID must be provided" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_not_called()

    @patch("aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports")
    def test_invalid_threat_objects(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.return_value = [ThreatScanReportObject()]
        report_ids = ["report_id_1", "report_id_2", None]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Report ID Can't be None or Empty" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_not_called()

        report_ids = ["report_id_1", "", "report_id_2"]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Report ID Can't be None or Empty" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_not_called()

    @patch(
        "aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
    )
    def test_get_threat_objects_exceed_max_ids(self, mock_get_threat_scan_reports_api):
        report_ids = ["id"] * (MAX_NUMBER_OF_REPORT_IDS + 1)
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue(
            f"The number of report_ids should not exceed {MAX_NUMBER_OF_REPORT_IDS}." in str(context.exception)
        )
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_not_called()

    @patch(
        "aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
    )
    def test_get_threat_objects_id_too_long(self, mock_get_threat_scan_reports_api):
        invalid_report_id = "a" * (MAX_REPORT_ID_STR_LENGTH + 1)
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects([invalid_report_id])
        self.assertTrue(f"Report ID '{invalid_report_id}' exceeds the maximum allowed length" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_not_called()

    @patch("aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports")
    def test_get_threat_objects_api_error(self, mock_scan_reports_api):
        mock_scan_reports_api.side_effect = Exception("Unexpected Error")

        report_ids = ["report_id_1"]
        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertIn("Unexpected Error", str(context.exception))

    @patch("aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports")
    def test_query_by_reports_request_client_timeout_error(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = TimeoutError("Request timed out")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Request timed out" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports")
    def test_query_by_reports_request_client_invalid_type_error(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = TypeError("Invalid type")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Invalid type" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports")
    def test_query_by_reports_request_client_invalid_value_error(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = ValueError("Invalid Value")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Invalid Value" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports")
    def test_query_by_reports_request_client_connection_error(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = ConnectionError("Network unreachable")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Network unreachable" in str(context.exception))
        self.assertEqual(ErrorType.AISEC_SDK_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports")
    def test_query_by_reports_internal_server_error(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = ApiException(status=500, reason="Internal Server Error")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Internal Server Error" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports")
    def test_query_by_reports_forbidden_exception_error(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = ApiException(status=403, reason="Forbidden")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Forbidden" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)

    @patch("aisecurity.scan.inline.query_by_report_ids.ScanReportsApi.get_threat_scan_reports")
    def test_query_by_reports_unauthorized_exception_error(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = ApiException(status=401, reason="Unauthorized")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Unauthorized" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)

    def test_singleton(self):
        another_instance = QueryByReportIds()
        self.assertIs(self.query_by_report_ids, another_instance)


if __name__ == "__main__":
    unittest.main()
