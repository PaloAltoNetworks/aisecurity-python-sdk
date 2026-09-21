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
from unittest.mock import MagicMock, patch

from urllib3.util import Retry

from aisecurity import global_configuration
from aisecurity.constants.base import (
    HEADER_API_KEY,
    HTTP_FORCE_RETRY_STATUS_CODES,
    USER_AGENT,
    HEADER_AUTH_TOKEN,
    BEARER,
)
from aisecurity.scan.inline.base import ApiBase, ScanApiBase


class TestApiBase(unittest.TestCase):
    @patch("aisecurity.scan.inline.base.ApiClient")
    def test_api_client_configuration(self, mock_api_client):
        mock_instance = MagicMock()
        mock_api_client.return_value = mock_instance

        global_configuration.api_endpoint = "https://test-endpoint.com"
        global_configuration.api_key = "test-api-key"
        global_configuration.num_retries = 3

        api_base = ApiBase()
        result = api_base.create_api_client()
        self.assertEqual(result, mock_instance)
        self.assertEqual(mock_instance.user_agent, USER_AGENT)
        mock_instance.set_default_header.assert_any_call(HEADER_API_KEY, "test-api-key")

        # Endpoint, retry policy and TLS defaults are carried on the
        # Configuration passed into ApiClient, so the REST pool is built with
        # them applied (rather than replacing the pool manager afterwards).
        config = mock_api_client.call_args.kwargs["configuration"]
        self.assertEqual(config.host, "https://test-endpoint.com")
        self.assertTrue(config.verify_ssl)
        self.assertIsNone(config.ssl_ca_cert)
        retries = config.retries
        self.assertIsInstance(retries, Retry)
        self.assertEqual(retries.total, global_configuration.num_retries)
        self.assertEqual(retries.status_forcelist, HTTP_FORCE_RETRY_STATUS_CODES)
        global_configuration.reset()

    @patch("aisecurity.scan.inline.base.ApiClient")
    def test_api_client_configuration_with_token(self, mock_api_client):
        mock_instance = MagicMock()
        mock_api_client.return_value = mock_instance

        global_configuration.api_endpoint = "https://test-endpoint.com"
        global_configuration.api_token = "test-api-token"

        api_base = ApiBase()
        result = api_base.create_api_client()
        self.assertEqual(result, mock_instance)
        self.assertEqual(mock_api_client.call_args.kwargs["configuration"].host, "https://test-endpoint.com")
        self.assertEqual(mock_instance.user_agent, USER_AGENT)
        mock_instance.set_default_header.assert_any_call(HEADER_AUTH_TOKEN, BEARER + "test-api-token")
        global_configuration.reset()

    @patch("aisecurity.scan.inline.base.ApiClient")
    def test_api_client_configuration_with_key_and_token(self, mock_api_client):
        mock_instance = MagicMock()
        mock_api_client.return_value = mock_instance

        global_configuration.api_endpoint = "https://test-endpoint.com"
        global_configuration.api_token = "test-api-token"
        global_configuration.api_key = "test-api-key"

        api_base = ApiBase()
        result = api_base.create_api_client()
        self.assertEqual(result, mock_instance)
        self.assertEqual(mock_api_client.call_args.kwargs["configuration"].host, "https://test-endpoint.com")
        self.assertEqual(mock_instance.user_agent, USER_AGENT)
        mock_instance.set_default_header.assert_any_call(HEADER_AUTH_TOKEN, BEARER + "test-api-token")
        mock_instance.set_default_header.assert_any_call(HEADER_API_KEY, "test-api-key")
        global_configuration.reset()

    @patch("aisecurity.scan.inline.base.ApiClient")
    def test_api_client_tls_headers_and_proxy(self, mock_api_client):
        mock_instance = MagicMock()
        mock_api_client.return_value = mock_instance

        global_configuration.api_endpoint = "https://test-endpoint.com"
        global_configuration.api_key = "test-api-key"
        # Simulate a fully configured transport (bypassing file-existence
        # validation performed by the public setters).
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

        # Caller header applied, and SDK auth header still present.
        mock_instance.set_default_header.assert_any_call("X-Env", "prod")
        mock_instance.set_default_header.assert_any_call(HEADER_API_KEY, "test-api-key")
        global_configuration.reset()

    @patch("aisecurity.scan.inline.base.ApiClient")
    def test_api_client_verify_disabled(self, mock_api_client):
        mock_instance = MagicMock()
        mock_api_client.return_value = mock_instance
        global_configuration.api_key = "test-api-key"
        global_configuration._verify = False

        ApiBase().create_api_client()
        config = mock_api_client.call_args.kwargs["configuration"]
        self.assertFalse(config.verify_ssl)
        global_configuration.reset()


class TestScanApiBase(unittest.TestCase):
    def setUp(self):
        self.scan_api_base = ScanApiBase()

    def test_scan_api_creation(self):
        self.assertIsNotNone(self.scan_api_base.scan_api)

    @patch("aisecurity.scan.inline.base.ScansApi")
    def test_scan_api_initialization(self, mock_scans_api):
        ScanApiBase()
        mock_scans_api.assert_called_once()


if __name__ == "__main__":
    unittest.main()
