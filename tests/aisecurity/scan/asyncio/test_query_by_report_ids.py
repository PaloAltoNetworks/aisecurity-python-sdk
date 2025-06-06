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

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import aiohttp

from aisecurity.constants.base import MAX_NUMBER_OF_REPORT_IDS, MAX_REPORT_ID_STR_LENGTH
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import ThreatScanReportObject
from aisecurity.generated_openapi_client.asyncio.exceptions import ApiException
from aisecurity.scan.asyncio.query_by_report_ids import QueryByReportIds


class TestQueryByReportIds(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.query_by_report_ids = QueryByReportIds()

    async def test_singleton_in_concurrent_tasks(self):
        async def get_instance():
            return QueryByReportIds()

        # Create multiple tasks to get AsyncScanExecutor instances
        tasks = [asyncio.create_task(get_instance()) for _ in range(10)]

        # Wait for all tasks to complete
        instances = await asyncio.gather(*tasks)

        # Check if all instances are the same
        first_instance = instances[0]
        for instance in instances[1:]:
            self.assertIs(instance, first_instance)
            self.assertEqual(id(instance), id(first_instance))

    # @pytest.mark.urllib3
    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_get_threat_scan_reports(self, mock_scan_reports_api):
        valid_report_ids = ["12345", "abcde", "valid_id"]
        mock_reports = [
            AsyncMock(spec=ThreatScanReportObject),
            AsyncMock(spec=ThreatScanReportObject),
        ]
        mock_scan_reports_api.return_value = mock_reports
        result = await self.query_by_report_ids.get_threat_objects(valid_report_ids)
        self.assertEqual(result, mock_reports)
        mock_scan_reports_api.assert_called_once_with(report_ids=valid_report_ids)

    # @pytest.mark.urllib3
    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_invalid_report_id_length(self, mock_get_threat_scan_reports_api):
        invalid_report_id = "a" * (MAX_REPORT_ID_STR_LENGTH + 1)
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects([invalid_report_id])

        self.assertTrue(f"Report ID '{invalid_report_id}' exceeds the maximum allowed length" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_not_called()

        report_ids = ["report_id1", "report_id2", None]
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Report ID Can't be None or Empty" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_not_called()

        report_ids = ["", "report_id2"]
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Report ID Can't be None or Empty" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_not_called()

    # @pytest.mark
    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_empty_report_ids(self, mock_get_threat_scan_reports_api):
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects([])
        self.assertTrue("At least one report ID must be provided" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_not_called()

    # @pytest.mark
    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_max_number_of_report_ids(self, mock_get_threat_scan_reports_api):
        max_report_ids = ["id" + str(i) for i in range(MAX_NUMBER_OF_REPORT_IDS)]
        mock_reports = [AsyncMock(spec=ThreatScanReportObject) for _ in range(MAX_NUMBER_OF_REPORT_IDS)]
        mock_get_threat_scan_reports_api.return_value = mock_reports
        result = await self.query_by_report_ids.get_threat_objects(max_report_ids)
        self.assertEqual(result, mock_reports)
        mock_get_threat_scan_reports_api.assert_called_once_with(report_ids=max_report_ids)

    # @pytest.mark
    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_exceed_max_number_of_report_ids(self, mock_get_threat_scan_reports_api):
        exceed_max_report_ids = ["id" + str(i) for i in range(MAX_NUMBER_OF_REPORT_IDS + 1)]
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects(exceed_max_report_ids)
        self.assertTrue(
            f"The number of report_ids should not exceed {MAX_NUMBER_OF_REPORT_IDS}." in str(context.exception)
        )
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.get_threat_scan_reports.assert_not_called()

    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_query_by_reports_request_client_timeout_error(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = aiohttp.ClientConnectionError("Request timed out")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Request timed out" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_called_once_with(report_ids=report_ids)

    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_query_by_reports_request_client_error(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = aiohttp.ClientError("Invalid URL")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("Invalid URL" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_called_once_with(report_ids=report_ids)

    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_query_by_reports_request_client_response_error(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = aiohttp.ClientResponseError(
            request_info=AsyncMock(),
            history=AsyncMock(),
            status=400,
            message="Bad request",
        )
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("400" in str(context.exception))
        self.assertTrue("Bad request" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_called_once_with(report_ids=report_ids)

    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_query_by_reports_request_api_server_exception(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = ApiException(status=500, reason="Internal Server Error")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("500" in str(context.exception))
        self.assertTrue("Internal Server Error" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_called_once_with(report_ids=report_ids)

    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_query_by_reports_unauthorized_exception(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = ApiException(status=401, reason="Unauthorized")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("401" in str(context.exception))
        self.assertTrue("Unauthorized" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_called_once_with(report_ids=report_ids)

    @patch(
        "aisecurity.scan.asyncio.query_by_report_ids.ScanReportsApi.get_threat_scan_reports",
        new_callable=AsyncMock,
    )
    async def test_query_by_reports_forbidden_exception(self, mock_get_threat_scan_reports_api):
        mock_get_threat_scan_reports_api.side_effect = ApiException(status=403, reason="Forbidden")
        report_ids = ["12345", "abcde", "valid_id"]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_report_ids.get_threat_objects(report_ids)

        self.assertTrue("403" in str(context.exception))
        self.assertTrue("Forbidden" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_get_threat_scan_reports_api.assert_called_once_with(report_ids=report_ids)

    # @pytest.mark.urllib3
    async def asyncTearDown(self):
        await self.query_by_report_ids.close()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
