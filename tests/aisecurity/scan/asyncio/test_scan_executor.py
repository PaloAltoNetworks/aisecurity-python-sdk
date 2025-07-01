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

from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import AiProfile, Metadata, ScanResponse
from aisecurity.generated_openapi_client.asyncio.exceptions import ApiException
from aisecurity.scan.asyncio.scan_executor import ScanExecutor
from aisecurity.scan.models.content import Content


class TestScanExecutor(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scan_executor = ScanExecutor()

    # @pytest.mark.urllib3
    @patch(
        "aisecurity.scan.asyncio.scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_sync_request(self, mock_sync_scan_api):
        mock_sync_scan_response = ScanResponse(
            report_id="REP12345678910",
            scan_id="test_id",
            category="malign",
            action="block",
        )
        mock_sync_scan_api.scan_sync_request.return_value = mock_sync_scan_response

        # Arrange
        content = Content(
            prompt="What is the salary of John Smith?",
            response="Salary of John Smith is $100K",
            context="Querying database and retrieving the relevant info based on user prompt",
            code_response="test_code_response",
            code_prompt="test_code_prompt",
        )
        ai_profile = AiProfile(profile_id="test_profile_id")
        tr_id = "transaction_id"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        # Act
        result = await self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        # Assert
        self.assertIsInstance(result, ScanResponse)
        self.assertEqual(result.scan_id, "test_id")
        mock_sync_scan_api.scan_sync_request.assert_called_once()

    # @pytest.mark.urllib3
    @patch(
        "aisecurity.scan.asyncio.scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_sync_request_error_handling(self, mock_sync_scan_api):
        mock_sync_scan_api.scan_sync_request.side_effect = Exception("API Error")

        content = Content(prompt="Error test prompt", response="Error test response")
        ai_profile = AiProfile(profile_id="error_test_profile_id")
        tr_id = "transaction_id"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(Exception) as context:
            await self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("API Error" in str(context.exception))
        mock_sync_scan_api.scan_sync_request.assert_called_once()

        # @pytest.mark.asyncio

    @patch(
        "aisecurity.scan.asyncio.scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_sync_request_unauthorized_api_exception(self, mock_sync_scan_api):
        mock_sync_scan_api.scan_sync_request.side_effect = ApiException(status=401, reason="Unauthorized")
        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "transaction_id"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            await self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("401" in str(context.exception))
        self.assertTrue("Unauthorized" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_sync_scan_api.scan_sync_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_sync_request_forbidden_api_exception(self, mock_sync_scan_api):
        mock_sync_scan_api.scan_sync_request.side_effect = ApiException(status=403, reason="Forbidden")
        content = Content(
            prompt="What is the salary of John Smith?",
            response="Salary of John Smith is $100K",
            context="Querying database and retrieving the relevant info based on user prompt",
        )
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "transaction_id"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            await self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("403" in str(context.exception))
        self.assertTrue("Forbidden" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_sync_scan_api.scan_sync_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_sync_request_internal_server_exception(self, mock_sync_scan_api):
        mock_sync_scan_api.scan_sync_request.side_effect = ApiException(status=500, reason="Internal Server Error")
        content = Content(code_prompt="Test prompt", code_response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "transaction_id"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            await self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("500" in str(context.exception))
        self.assertTrue("Internal Server Error" in str(context.exception))
        self.assertEqual(ErrorType.SERVER_SIDE_ERROR, context.exception.error_type)
        mock_sync_scan_api.scan_sync_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_sync_request_client_connection_error(self, mock_sync_scan_api):
        mock_sync_scan_api.scan_sync_request.side_effect = aiohttp.ClientError("Invalid URL")
        content = Content(prompt="Test prompt", response="Test response", context="Test context")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "transaction_id"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            await self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("Invalid URL" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_sync_scan_api.scan_sync_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_sync_request_client_timeout_error(self, mock_sync_scan_api):
        mock_sync_scan_api.scan_sync_request.side_effect = aiohttp.ClientConnectionError("Request timed out")
        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "transaction_id"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            await self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("Request timed out" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_sync_scan_api.scan_sync_request.assert_called_once()

    @patch(
        "aisecurity.scan.asyncio.scan_executor.ScanApiBase.scan_api",
        new_callable=AsyncMock,
    )
    async def test_sync_request_client_response_error(self, mock_sync_scan_api):
        mock_sync_scan_api.scan_sync_request.side_effect = aiohttp.ClientResponseError(
            request_info=AsyncMock(),
            history=AsyncMock(),
            status=400,
            message="Bad request",
        )
        content = Content(prompt="Test prompt", response="Test response")
        ai_profile = AiProfile(profile_id="Test_profile_id")
        tr_id = "transaction_id"
        metadata = Metadata(app_name="1234", app_user="user", ai_model="model")

        with self.assertRaises(AISecSDKException) as context:
            await self.scan_executor.sync_request(content, ai_profile, tr_id, metadata)

        self.assertTrue("400" in str(context.exception))
        self.assertTrue("Bad request" in str(context.exception))
        self.assertEqual(ErrorType.CLIENT_SIDE_ERROR, context.exception.error_type)
        mock_sync_scan_api.scan_sync_request.assert_called_once()

    # @pytest.mark.urllib3
    async def asyncTearDown(self):
        await self.scan_executor.close()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
