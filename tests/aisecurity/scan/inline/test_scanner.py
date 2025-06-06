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
from unittest.mock import MagicMock, Mock, patch

from aisecurity.generated_openapi_client import (
    AiProfile,
    AsyncScanObject,
    ScanRequest,
    ScanRequestContentsInner,
)
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner()

    @patch("aisecurity.scan.inline.scanner.ScanExecutor")
    def test_sync_scan(self, mock_scan_executor):
        mock_instance = MagicMock()
        mock_scan_executor.return_value = mock_instance
        mock_instance.sync_request.return_value = "mock_response"

        ai_profile = Mock(spec=AiProfile)
        content = Mock(spec=Content)

        response = self.scanner.sync_scan(ai_profile, content)

        self.assertEqual(response, "mock_response")
        mock_instance.sync_request.assert_called_once_with(
            ai_profile=ai_profile, content=content, tr_id=None, metadata=None
        )

    @patch("aisecurity.scan.inline.scanner.AsyncScanExecutor")
    def test_async_scan(self, mock_async_scan_executor):
        mock_instance = MagicMock()
        mock_async_scan_executor.return_value = mock_instance
        mock_instance.async_request.return_value = "mock_async_response"

        async_scan_objects = [
            AsyncScanObject(
                req_id=1234,
                scan_req=ScanRequest(
                    tr_id="test",
                    ai_profile=AiProfile(
                        profile_id="test",
                    ),
                    contents=[
                        ScanRequestContentsInner(
                            prompt="This is a mock tests prompt with google.com url",
                            response="This is a mock tests response",
                        )
                    ],
                ),
            )
        ]

        response = self.scanner.async_scan(async_scan_objects)

        self.assertEqual(response, "mock_async_response")
        mock_instance.async_request.assert_called_once_with(scan_objects=async_scan_objects)

    @patch("aisecurity.scan.inline.scanner.QueryByScanIds")
    def test_query_by_scan_ids(self, mock_query_by_scan_ids):
        mock_instance = MagicMock()
        mock_query_by_scan_ids.return_value = mock_instance
        mock_instance.get_scan_results.return_value = "mock_scan_results"

        scan_ids = ["id1", "id2"]

        response = self.scanner.query_by_scan_ids(scan_ids)

        self.assertEqual(response, "mock_scan_results")
        mock_instance.get_scan_results.assert_called_once_with(scan_ids=scan_ids)

    @patch("aisecurity.scan.inline.scanner.QueryByReportIds")
    def test_query_by_report_ids(self, mock_query_by_report_ids):
        mock_instance = MagicMock()
        mock_query_by_report_ids.return_value = mock_instance
        mock_instance.get_threat_objects.return_value = "mock_threat_objects"

        report_ids = ["report1", "report2"]

        response = self.scanner.query_by_report_ids(report_ids)

        self.assertEqual(response, "mock_threat_objects")
        mock_instance.get_threat_objects.assert_called_once_with(report_ids=report_ids)

    @patch("aisecurity.scan.inline.scanner.ScanExecutor")
    @patch("aisecurity.scan.inline.scanner.AsyncScanExecutor")
    @patch("aisecurity.scan.inline.scanner.QueryByScanIds")
    @patch("aisecurity.scan.inline.scanner.QueryByReportIds")
    async def test_close(self, mock_query_report, mock_query_scan, mock_async_exec, mock_sync_exec):
        scanner = Scanner()

        # Initialize all executors
        scanner.sync_scan(AiProfile(), Content())
        scanner.async_scan([AsyncScanObject()])
        scanner.query_by_scan_ids(["id"])
        scanner.query_by_report_ids(["report"])

        mock_sync_exec.return_value.close.assert_called_once()
        mock_async_exec.return_value.close.assert_called_once()
        mock_query_scan.return_value.close.assert_called_once()
        mock_query_report.return_value.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
