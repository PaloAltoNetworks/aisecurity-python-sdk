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
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp_retry

from aisecurity import global_configuration
from aisecurity.constants.base import (
    HEADER_API_KEY,
    HEADER_AUTH_TOKEN,
    HTTP_FORCE_RETRY_STATUS_CODES,
    MAX_CONNECTION_POOL_SIZE,
    USER_AGENT,
    BEARER,
)
from aisecurity.scan.asyncio.base import ApiBase, ScanApiBase


class TestApiBase(unittest.IsolatedAsyncioTestCase):
    @patch("aisecurity.scan.asyncio.base.ApiClient")
    def test_create_api_client(self, mock_api_client):
        # Arrange
        mock_instance = MagicMock()
        mock_api_client.return_value = mock_instance
        global_configuration.api_endpoint = "https://test-api.example.com"
        global_configuration.api_key = "test-api-key"
        global_configuration.num_retries = 3

        # Act
        api_base = ApiBase()
        result = api_base.create_api_client()

        # Assert
        self.assertEqual(result, mock_instance)
        self.assertEqual(mock_instance.user_agent, USER_AGENT)
        mock_instance.set_default_header.assert_any_call(HEADER_API_KEY, "test-api-key")

        # Endpoint, pool size and TLS settings are carried on the Configuration
        # passed into ApiClient, so the aiohttp session/SSL context is built
        # with them applied.
        config = mock_api_client.call_args.kwargs["configuration"]
        self.assertEqual(config.connection_pool_maxsize, MAX_CONNECTION_POOL_SIZE)
        self.assertEqual(config.host, "https://test-api.example.com")
        self.assertTrue(config.verify_ssl)

        # The SDK wraps the session with retry-on-status behaviour.
        retry_client = result.rest_client.retry_client
        self.assertIsInstance(retry_client, aiohttp_retry.RetryClient)
        self.assertIsInstance(retry_client.retry_options, aiohttp_retry.ExponentialRetry)
        self.assertEqual(retry_client.retry_options.attempts, global_configuration.num_retries)
        self.assertEqual(
            retry_client.retry_options.statuses,
            set(HTTP_FORCE_RETRY_STATUS_CODES),
        )
        global_configuration.reset()

    @patch("aisecurity.scan.asyncio.base.ApiClient")
    def test_create_api_client_with_token(self, mock_api_client):
        # Arrange
        mock_instance = MagicMock()
        mock_api_client.return_value = mock_instance
        global_configuration.api_endpoint = "https://test-api.example.com"
        global_configuration.api_token = "test-api-token"

        # Act
        api_base = ApiBase()
        result = api_base.create_api_client()
        self.assertEqual(result, mock_instance)
        self.assertEqual(mock_api_client.call_args.kwargs["configuration"].host, "https://test-api.example.com")
        self.assertEqual(mock_instance.user_agent, USER_AGENT)
        mock_instance.set_default_header.assert_any_call(HEADER_AUTH_TOKEN, BEARER + "test-api-token")
        global_configuration.reset()

    @patch("aisecurity.scan.asyncio.base.ApiClient")
    def test_create_api_client_with_key_and_token(self, mock_api_client):
        # Arrange
        mock_instance = MagicMock()
        mock_api_client.return_value = mock_instance
        global_configuration.api_endpoint = "https://test-api.example.com"
        global_configuration.api_token = "test-api-token"
        global_configuration.api_key = "test-api-key"

        # Act
        api_base = ApiBase()
        result = api_base.create_api_client()
        self.assertEqual(result, mock_instance)
        self.assertEqual(mock_api_client.call_args.kwargs["configuration"].host, "https://test-api.example.com")
        self.assertEqual(mock_instance.user_agent, USER_AGENT)
        mock_instance.set_default_header.assert_any_call(HEADER_AUTH_TOKEN, BEARER + "test-api-token")
        mock_instance.set_default_header.assert_any_call(HEADER_API_KEY, "test-api-key")
        global_configuration.reset()

    @patch("aisecurity.scan.asyncio.base.ApiClient")
    def test_create_api_client_tls_headers_and_proxy(self, mock_api_client):
        mock_instance = MagicMock()
        mock_api_client.return_value = mock_instance
        global_configuration.api_endpoint = "https://test-api.example.com"
        global_configuration.api_key = "test-api-key"
        global_configuration._verify = "/etc/ssl/ca-bundle.pem"
        global_configuration._ssl_ca_cert = "/etc/ssl/ca-bundle.pem"
        global_configuration._cert_file = "/etc/ssl/client.crt"
        global_configuration._key_file = "/etc/ssl/client.key"
        global_configuration._custom_headers = {"X-Env": "prod"}
        global_configuration._proxy = "http://proxy.local:8080"
        global_configuration._proxy_headers = {"Proxy-Auth": "abc"}

        result = ApiBase().create_api_client()
        self.assertEqual(result, mock_instance)

        config = mock_api_client.call_args.kwargs["configuration"]
        self.assertTrue(config.verify_ssl)
        self.assertEqual(config.ssl_ca_cert, "/etc/ssl/ca-bundle.pem")
        self.assertEqual(config.cert_file, "/etc/ssl/client.crt")
        self.assertEqual(config.key_file, "/etc/ssl/client.key")
        self.assertEqual(config.proxy, "http://proxy.local:8080")
        self.assertEqual(config.proxy_headers, {"Proxy-Auth": "abc"})

        mock_instance.set_default_header.assert_any_call("X-Env", "prod")
        mock_instance.set_default_header.assert_any_call(HEADER_API_KEY, "test-api-key")
        global_configuration.reset()


class TestScanApiBase(unittest.IsolatedAsyncioTestCase):
    @patch("aisecurity.scan.asyncio.base.ApiBase.create_api_client", new_callable=AsyncMock)
    def test_scan_api_creation(self, mock_api_client):
        scan_api_base = ScanApiBase()
        self.assertIsNotNone(scan_api_base.scan_api)
        mock_api_client.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
