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
from unittest.mock import AsyncMock, patch

from aisecurity.generated_openapi_client import AiProfile, AsyncScanObject, Metadata
from aisecurity.scan.asyncio.scanner import Scanner
from aisecurity.scan.models.content import Content


class TestScanner(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scanner = Scanner()

    @patch("aisecurity.scan.asyncio.scanner.ScanExecutor")
    async def test_sync_scan(self, mock_scan_executor):
        mock_executor = AsyncMock()
        mock_scan_executor.return_value = mock_executor
        mock_executor.sync_request.return_value = "mocked_response"

        ai_profile = AsyncMock(spec=AiProfile)
        content = AsyncMock(spec=Content)
        tr_id = AsyncMock(spec=str)
        metadata = AsyncMock(spec=Metadata)

        response = await self.scanner.sync_scan(ai_profile, content, tr_id=tr_id, metadata=metadata)

        self.assertEqual(response, "mocked_response")
        # 1 second in milliseconds
        mock_executor.sync_request.assert_called_once_with(
            ai_profile=ai_profile, content=content, tr_id=tr_id, metadata=metadata
        )

    @patch("aisecurity.scan.asyncio.scanner.AsyncScanExecutor")
    async def test_async_scan(self, mock_scan_request):
        mock_request = AsyncMock()
        mock_scan_request.return_value = mock_request
        mock_request.async_request.return_value = "mocked_async_response"

        async_scan_objects = [
            AsyncMock(spec=AsyncScanObject),
            AsyncMock(spec=AsyncScanObject),
        ]

        response = await self.scanner.async_scan(async_scan_objects)

        self.assertEqual(response, "mocked_async_response")
        mock_request.async_request.assert_called_once_with(scan_objects=async_scan_objects)

    @patch("aisecurity.scan.asyncio.scanner.QueryByScanIds")
    async def test_query_by_scan_ids(self, mock_query_by_scan_ids):
        mock_query = AsyncMock()
        mock_query_by_scan_ids.return_value = mock_query
        mock_query.get_scan_results.return_value = "mocked_scan_id_responses"

        scan_ids = ["id1", "id2", "id3"]

        response = await self.scanner.query_by_scan_ids(scan_ids)

        self.assertEqual(response, "mocked_scan_id_responses")
        mock_query.get_scan_results.assert_called_once_with(scan_ids=scan_ids)

    @patch("aisecurity.scan.asyncio.scanner.QueryByReportIds")
    async def test_query_by_report_ids(self, mock_query_by_report_id):
        mock_query = AsyncMock()
        mock_query_by_report_id.return_value = mock_query
        mock_query.get_threat_objects.return_value = "mocked_report_id_responses"

        report_ids = ["report1", "report2", "report3"]

        response = await self.scanner.query_by_report_ids(report_ids)

        self.assertEqual(response, "mocked_report_id_responses")
        mock_query.get_threat_objects.assert_called_once_with(report_ids=report_ids)

    async def asyncTearDown(self):
        await self.scanner.close()


if __name__ == "__main__":
    unittest.main()
