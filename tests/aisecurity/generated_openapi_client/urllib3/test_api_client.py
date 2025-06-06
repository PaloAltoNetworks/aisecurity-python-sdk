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

import hashlib
import hmac
import json
import unittest
from unittest.mock import Mock, patch

from aisecurity.constants.base import HEADER_API_KEY, PAYLOAD_HASH
from aisecurity.generated_openapi_client.urllib3.api_client import ApiClient
from aisecurity.generated_openapi_client.urllib3.rest import RESTResponse


class TestApiClient(unittest.TestCase):
    def setUp(self):
        self.api_client = ApiClient()

    def test_init(self):
        self.assertEqual(self.api_client.user_agent, "OpenAPI-Generator/1.0.0/python")
        self.assertEqual(
            self.api_client.default_headers["User-Agent"],
            "OpenAPI-Generator/1.0.0/python",
        )

    def test_set_default_header(self):
        self.api_client.set_default_header("Test-Header", "Test-Value")
        self.assertEqual(self.api_client.default_headers["Test-Header"], "Test-Value")

    def test_user_agent_setter(self):
        self.api_client.user_agent = "Custom-User-Agent"
        self.assertEqual(self.api_client.default_headers["User-Agent"], "Custom-User-Agent")

    @patch("aisecurity.generated_openapi_client.urllib3.rest.RESTClientObject")
    def test_call_api(self, mock_rest_client):
        mock_response = Mock(spec=RESTResponse)
        mock_rest_client.return_value.request.return_value = mock_response

        self.api_client.rest_client = mock_rest_client.return_value

        method = "POST"
        url = "https://api.example.com/endpoint"
        header_params = {HEADER_API_KEY: "test_api_key"}
        body = {"key": "value"}

        response = self.api_client.call_api(method, url, header_params, body)

        self.assertEqual(response, mock_response)
        mock_rest_client.return_value.request.assert_called_once()

        call_args = mock_rest_client.return_value.request.call_args
        self.assertEqual(call_args[0][0], method)
        self.assertEqual(call_args[0][1], url)
        self.assertIn(PAYLOAD_HASH, call_args[1]["headers"])
        api_key = "test_api_key"
        expected_hash = hmac.new(
            key=api_key.encode("utf-8"),
            msg=json.dumps(body).encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()
        self.assertEqual(call_args[1]["headers"][PAYLOAD_HASH], expected_hash)

    @patch("aisecurity.generated_openapi_client.urllib3.rest.RESTClientObject")
    def test_call_api_exception(self, mock_rest_client):
        mock_rest_client.return_value.request.side_effect = Exception("Test exception")

        self.api_client.rest_client = mock_rest_client.return_value

        method = "GET"
        url = "https://api.example.com/endpoint"
        header_params = {HEADER_API_KEY: "test_api_key"}
        body = {"key": "value"}

        with self.assertRaises(Exception) as context:
            self.api_client.call_api(method, url, header_params, body)

        self.assertIn(str(context.exception), "Test exception")

    @patch("aisecurity.utils.Utils.generate_payload_hash")
    @patch("aisecurity.generated_openapi_client.urllib3.rest.RESTClientObject")
    def test_call_api_hashlib_exception(self, mock_rest_client, mock_sha256):
        mock_sha256.side_effect = ImportError("Import error")

        self.api_client.rest_client = mock_rest_client.return_value

        method = "POST"
        url = "https://api.example.com/endpoint"
        header_params = {HEADER_API_KEY: "test_api_key"}
        body = {"key": "value"}

        with self.assertRaises(ImportError) as context:
            self.api_client.call_api(method, url, header_params, body)

        self.assertEqual(str(context.exception), "Import error")

    @patch("aisecurity.utils.Utils.generate_payload_hash")
    @patch("aisecurity.generated_openapi_client.urllib3.rest.RESTClientObject")
    def test_call_api_hashlib_value_exception(self, mock_rest_client, mock_sha256):
        mock_sha256.side_effect = ValueError("Value error")

        self.api_client.rest_client = mock_rest_client.return_value

        method = "POST"
        url = "https://api.example.com/endpoint"
        header_params = {HEADER_API_KEY: "test_api_key"}
        body = {"key": "value"}

        with self.assertRaises(ValueError) as context:
            self.api_client.call_api(method, url, header_params, body)

        self.assertEqual(str(context.exception), "Value error")


if __name__ == "__main__":
    unittest.main()
