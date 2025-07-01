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

import json
import unittest
from unittest.mock import AsyncMock, patch

from aisecurity.constants.base import HEADER_API_KEY, PAYLOAD_HASH
from aisecurity.generated_openapi_client.asyncio.api_client import ApiClient
from aisecurity.generated_openapi_client.asyncio.exceptions import ApiException
from aisecurity.generated_openapi_client.asyncio.rest import RESTResponse


class TestApiClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        with patch("aisecurity.generated_openapi_client.asyncio.rest.aiohttp.TCPConnector"):
            self.api_client = ApiClient()

    async def test_call_api(self):
        # Mock the REST client
        self.api_client.rest_client = AsyncMock()
        mock_response = RESTResponse(AsyncMock(status=200, reason="OK", headers={"Content-Type": "application/json"}))
        mock_response.data = b'{"result": "success"}'
        self.api_client.rest_client.request.return_value = mock_response

        # Test parameters
        method = "POST"
        url = "https://api.example.com/endpoint"
        header_params = {HEADER_API_KEY: "test_api_key"}
        body = {"key": "value"}
        post_params = None
        request_timeout = 30

        # Call the method
        response = await self.api_client.call_api(method, url, header_params, body, post_params, request_timeout)

        # Assertions
        self.assertIsInstance(response, RESTResponse)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.data, b'{"result": "success"}')

        # Check if the PAYLOAD_HASH was added to the header
        self.api_client.rest_client.request.assert_called_once()
        call_args = self.api_client.rest_client.request.call_args
        self.assertIn(PAYLOAD_HASH, call_args[1]["headers"])

        # Verify the hash
        import hashlib
        import hmac

        api_key = "test_api_key"
        expected_hash = hmac.new(
            key=api_key.encode("utf-8"),
            msg=json.dumps(body).encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()
        self.assertEqual(call_args[1]["headers"][PAYLOAD_HASH], expected_hash)

        # Check other parameters
        self.assertEqual(call_args[0][0], method)
        self.assertEqual(call_args[0][1], url)
        self.assertEqual(call_args[1]["body"], body)
        self.assertEqual(call_args[1]["post_params"], post_params)
        self.assertEqual(call_args[1]["_request_timeout"], request_timeout)

    async def test_call_api_exception(self):
        # Mock the REST client to raise an exception
        self.api_client.rest_client = AsyncMock()
        self.api_client.rest_client.request.side_effect = ApiException("Test exception")

        # Test parameters
        method = "GET"
        url = "https://api.example.com/endpoint"
        header_params = {HEADER_API_KEY: "test_api_key"}
        body = {"key": "value"}

        # Call the method and check for exception
        with self.assertRaisesRegex(ApiException, "Test exception"):
            await self.api_client.call_api(method, url, header_params, body)

    async def test_call_api_hashlib_exception(self):
        # Mock hashlib to raise an exception
        with patch("aisecurity.utils.Utils.generate_payload_hash") as mock_sha256:
            mock_sha256.side_effect = AttributeError("Attribute error")

            # Test parameters
            method = "POST"
            url = "https://api.example.com/endpoint"
            header_params = {HEADER_API_KEY: "test_api_key"}
            body = {"key": "value"}

            # Call the method and check for exception
            with self.assertRaisesRegex(AttributeError, "Attribute error"):
                await self.api_client.call_api(method, url, header_params, body)

        # Verify that the exception was raised
        mock_sha256.assert_called_once()

    async def test_call_api_hashlib_value_exception(self):
        # Mock hashlib to raise an exception
        with patch("aisecurity.utils.Utils.generate_payload_hash") as mock_sha256:
            mock_sha256.side_effect = ValueError("Value error")

            # Test parameters
            method = "POST"
            url = "https://api.example.com/endpoint"
            header_params = {HEADER_API_KEY: "test_api_key"}
            body = {"key": "value"}

            # Call the method and check for exception
            with self.assertRaisesRegex(ValueError, "Value error"):
                await self.api_client.call_api(method, url, header_params, body)

        # Verify that the exception was raised
        mock_sha256.assert_called_once()


if __name__ == "__main__":
    unittest.main()
