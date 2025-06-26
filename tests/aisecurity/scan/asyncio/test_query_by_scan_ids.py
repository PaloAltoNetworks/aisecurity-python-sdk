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
import uuid
from unittest.mock import AsyncMock, patch

import aiohttp

from aisecurity.constants.base import MAX_NUMBER_OF_SCAN_IDS, MAX_SCAN_ID_STR_LENGTH
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import ScanIdResult
from aisecurity.generated_openapi_client.asyncio.exceptions import ApiException
from aisecurity.scan.asyncio.query_by_scan_ids import QueryByScanIds


class TestQueryByScanIds(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.query_by_scan_ids = QueryByScanIds()

    # @pytest.mark.urllib3
    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_get_threat_scan_reports(self, mock_get_scan_results_by_scan_ids_api):
        scan_ids = [str(uuid.uuid4()) for _ in range(MAX_NUMBER_OF_SCAN_IDS - 1)]
        mock_scan_results = [AsyncMock(spec=ScanIdResult), AsyncMock(spec=ScanIdResult)]
        mock_get_scan_results_by_scan_ids_api.return_value = mock_scan_results
        result = await self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertEqual(result, mock_scan_results)
        mock_get_scan_results_by_scan_ids_api.assert_called_once_with(scan_ids=scan_ids)

    # @pytest.mark.urllib3
    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_scan_id_length_validation(self, mock_get_scan_results_by_scan_ids_api):
        invalid_scan_id = "a" * (MAX_SCAN_ID_STR_LENGTH + 1)
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results([invalid_scan_id])

        self.assertIn("exceeds the maximum allowed length", str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

    # @pytest.mark.urllib3
    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_mixed_scan_id_lengths(self, mock_get_scan_results_by_scan_ids_api):
        valid_scan_id = str(uuid.uuid4())
        invalid_scan_id = "a" * (MAX_SCAN_ID_STR_LENGTH + 1)

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results([valid_scan_id, invalid_scan_id])

        self.assertIn("exceeds the maximum allowed length", str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

    # @pytest.mark.urllib3
    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_empty_scan_ids(self, mock_get_scan_results_by_scan_ids_api):
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results([])
        self.assertIn("At least one scan ID must be provided", str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

    # @pytest.mark.urllib3
    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_max_scan_ids(self, mock_get_scan_results_by_scan_ids_api):
        valid_scan_ids = [str(uuid.uuid4()) for _ in range(MAX_NUMBER_OF_SCAN_IDS)]
        too_many_scan_ids = [*valid_scan_ids, str(uuid.uuid4())]

        # Test with maximum allowed scan IDs
        await self.query_by_scan_ids.get_scan_results(valid_scan_ids)
        mock_get_scan_results_by_scan_ids_api.assert_called_once_with(scan_ids=valid_scan_ids)
        mock_get_scan_results_by_scan_ids_api.reset_mock()

        # Test with too many scan IDs
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results(too_many_scan_ids)
        self.assertIn(
            f"Number of report IDs exceeds the maximum allowed ({MAX_NUMBER_OF_SCAN_IDS})",
            str(context.exception),
        )
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_invalid_scan_id_formats(self, mock_get_scan_results_by_scan_ids_api):
        scan_ids = ["fake_scan_id"]
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertIn(
            "Scan ID format must be in UUID format",
            str(context.exception),
        )
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

        scan_ids = [str(uuid.uuid4()), str(uuid.uuid4()), None]
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertIn(
            "Scan Id can't be None or empty",
            str(context.exception),
        )
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

        scan_ids = ["", str(uuid.uuid4())]
        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results(scan_ids)
        self.assertIn(
            "Scan Id can't be None or empty",
            str(context.exception),
        )
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_not_called()

    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_query_by_scan_request_client_timeout_error(self, mock_get_scan_results_by_scan_ids_api):
        mock_get_scan_results_by_scan_ids_api.side_effect = aiohttp.ClientConnectionError("Request timed out")
        scan_ids = [str(uuid.uuid4()) for _ in range(MAX_NUMBER_OF_SCAN_IDS - 1)]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results(scan_ids)

        self.assertTrue("Request timed out" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_called_once_with(scan_ids=scan_ids)

    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_query_by_scan_request_client_response_error(self, mock_get_scan_results_by_scan_ids_api):
        mock_get_scan_results_by_scan_ids_api.side_effect = aiohttp.ClientResponseError(
            request_info=AsyncMock(),
            history=AsyncMock(),
            status=400,
            message="Bad request",
        )
        scan_ids = [str(uuid.uuid4()) for _ in range(MAX_NUMBER_OF_SCAN_IDS - 1)]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results(scan_ids)

        self.assertTrue("400" in str(context.exception))
        self.assertTrue("Bad request" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_called_once_with(scan_ids=scan_ids)

    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_query_by_scan_request_client_error(self, mock_get_scan_results_by_scan_ids_api):
        mock_get_scan_results_by_scan_ids_api.side_effect = aiohttp.ClientError("Invalid Value")
        scan_ids = [str(uuid.uuid4()) for _ in range(MAX_NUMBER_OF_SCAN_IDS - 1)]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results(scan_ids)

        self.assertTrue("Invalid Value" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_called_once_with(scan_ids=scan_ids)

    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_query_by_scan_request_api_server_exception(self, mock_get_scan_results_by_scan_ids_api):
        mock_get_scan_results_by_scan_ids_api.side_effect = ApiException(status=500, reason="Internal Server Error")
        scan_ids = [str(uuid.uuid4()) for _ in range(MAX_NUMBER_OF_SCAN_IDS - 1)]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results(scan_ids)

        self.assertTrue("500" in str(context.exception))
        self.assertTrue("Internal Server Error" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_called_once_with(scan_ids=scan_ids)

    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_query_by_scan_request_forbidden_exception(self, mock_get_scan_results_by_scan_ids_api):
        mock_get_scan_results_by_scan_ids_api.side_effect = ApiException(status=403, reason="Forbidden")
        scan_ids = [str(uuid.uuid4()) for _ in range(MAX_NUMBER_OF_SCAN_IDS - 1)]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results(scan_ids)

        self.assertTrue("403" in str(context.exception))
        self.assertTrue("Forbidden" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_called_once_with(scan_ids=scan_ids)

    @patch(
        "aisecurity.scan.asyncio.query_by_scan_ids.ScanResultsApi.get_scan_results_by_scan_ids",
        new_callable=AsyncMock,
    )
    async def test_query_by_scan_request_unauthorized_exception(self, mock_get_scan_results_by_scan_ids_api):
        mock_get_scan_results_by_scan_ids_api.side_effect = ApiException(status=401, reason="Unauthorized")
        scan_ids = [str(uuid.uuid4()) for _ in range(MAX_NUMBER_OF_SCAN_IDS - 1)]

        with self.assertRaises(AISecSDKException) as context:
            await self.query_by_scan_ids.get_scan_results(scan_ids)

        self.assertTrue("401" in str(context.exception))
        self.assertTrue("Unauthorized" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_get_scan_results_by_scan_ids_api.assert_called_once_with(scan_ids=scan_ids)

    # @pytest.mark.urllib3
    async def asyncTearDown(self):
        await self.query_by_scan_ids.close()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
