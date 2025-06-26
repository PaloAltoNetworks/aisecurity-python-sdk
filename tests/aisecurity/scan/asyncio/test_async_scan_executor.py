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
from datetime import datetime
from unittest.mock import AsyncMock, patch

import aiohttp

from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import AsyncScanObject, AsyncScanResponse
from aisecurity.generated_openapi_client.asyncio.exceptions import ApiException
from aisecurity.scan.asyncio.async_scan_executor import AsyncScanExecutor


class TestAsyncScanExecutor(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_scan_executor = AsyncScanExecutor()

    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_async_request(self, mock_async_scan_api):
        mock_response = AsyncScanResponse(
            received=datetime(2024, 11, 21, 20, 21, 11, 855863),
            scan_id="test_id",
        )

        # Set up the mock to return this response when scan_async_request is called
        mock_async_scan_api.scan_async_request.return_value = mock_response
        async_scan_objects = AsyncMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        result = await self.async_scan_executor.async_request(scan_objects)
        self.assertIsInstance(result, AsyncScanResponse)
        self.assertEqual(result.scan_id, "test_id")
        mock_async_scan_api.scan_async_request.assert_called_once_with(async_scan_object=scan_objects)

    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_async_request_error_handling(self, mock_async_scan_api):
        mock_async_scan_api.scan_async_request.side_effect = Exception("API Error")

        async_scan_objects = AsyncMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(Exception) as context:
            await self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("API Error" in str(context.exception))
        mock_async_scan_api.scan_async_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.logger",
        new_callable=AsyncMock,
    )
    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_async_request_logs_error(self, mock_async_scan_api, mock_logger):
        mock_async_scan_api.scan_async_request.side_effect = Exception("API Error")

        scan_objects = [AsyncMock(spec=AsyncScanObject)]
        with self.assertRaises(Exception):
            await self.async_scan_executor.async_request(scan_objects)

        mock_logger.error.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_async_request_for_empty_scan_objects(self, mock_async_scan_api):
        scan_objects = []

        with self.assertRaises(AISecSDKException) as context:
            await self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("No scan objects are provided" in str(context.exception))
        self.assertEqual(ErrorType.USER_REQUEST_PAYLOAD_ERROR, context.exception.error_type)
        mock_async_scan_api.scan_async_request.assert_not_called()

    # @pytest.mark.asyncio
    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_async_request_internal_server_exception(self, mock_async_scan_api):
        mock_async_scan_api.scan_async_request.side_effect = ApiException(status=500, reason="Internal Server Error")
        async_scan_objects = AsyncMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            await self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("500" in str(context.exception))
        self.assertTrue("Internal Server Error" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_async_scan_api.scan_async_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_async_request_unauthorized_exception(self, mock_async_scan_api):
        mock_async_scan_api.scan_async_request.side_effect = ApiException(status=401, reason="Unauthorized")
        async_scan_objects = AsyncMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            await self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("401" in str(context.exception))
        self.assertTrue("Unauthorized" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_async_scan_api.scan_async_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_async_request_forbidden_exception(self, mock_async_scan_api):
        mock_async_scan_api.scan_async_request.side_effect = ApiException(status=403, reason="Forbidden")
        async_scan_objects = AsyncMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            await self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("403" in str(context.exception))
        self.assertTrue("Forbidden" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_async_scan_api.scan_async_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_async_request_client_error(self, mock_async_scan_api):
        mock_async_scan_api.scan_async_request.side_effect = aiohttp.ClientError("Invalid URL")
        async_scan_objects = AsyncMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            await self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("Invalid URL" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_async_scan_api.scan_async_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_async_request_client_connection_error(self, mock_async_scan_api):
        mock_async_scan_api.scan_async_request.side_effect = aiohttp.ClientConnectionError("Request timed out")
        async_scan_objects = AsyncMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            await self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("Request timed out" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_async_scan_api.scan_async_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.async_scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_async_request_client_response_error(self, mock_async_scan_api):
        mock_async_scan_api.scan_async_request.side_effect = aiohttp.ClientResponseError(
            request_info=AsyncMock(),
            history=AsyncMock(),
            status=400,
            message="Bad request",
        )
        async_scan_objects = AsyncMock(spec=AsyncScanObject)
        scan_objects = [async_scan_objects]

        with self.assertRaises(AISecSDKException) as context:
            await self.async_scan_executor.async_request(scan_objects)

        self.assertTrue("400" in str(context.exception))
        self.assertTrue("Bad request" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_async_scan_api.scan_async_request.assert_called_once()

    async def asyncTearDown(self):
        await self.async_scan_executor.close()

        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
