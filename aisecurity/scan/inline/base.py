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

from urllib3.util import Retry

from aisecurity import global_configuration
from aisecurity.constants.base import (
    HEADER_API_KEY,
    HTTP_FORCE_RETRY_STATUS_CODES,
    USER_AGENT,
    HEADER_AUTH_TOKEN,
    BEARER,
)
from aisecurity.generated_openapi_client.urllib3.api.scans_api import ScansApi
from aisecurity.generated_openapi_client.urllib3.api_client import ApiClient
from aisecurity.generated_openapi_client.urllib3.configuration import Configuration
from aisecurity.logger import BaseLogger


class ApiBase(BaseLogger):
    def __init__(self):
        super().__init__()
        self.__api_client = self.create_api_client()

    @property
    def api_client(self):
        return self.__api_client

    def create_api_client(self):
        # Build the transport configuration up front so the REST client's
        # PoolManager is created with the TLS/cert settings applied. urllib3
        # accepts a Retry object for ``retries``, which preserves the
        # status-code retry behaviour while keeping the SSL pool arguments.
        configuration = Configuration()
        # urllib3's PoolManager accepts a Retry object for ``retries`` (it is
        # passed straight through in the generated rest client), which lets us
        # retry on specific HTTP status codes. The generated stub narrows the
        # annotation to Optional[int], so the assignment is ignored for typing.
        configuration.retries = Retry(  # type: ignore[assignment]
            total=global_configuration.num_retries,
            status_forcelist=HTTP_FORCE_RETRY_STATUS_CODES,
        )
        configuration.verify_ssl = global_configuration.verify_ssl
        configuration.ssl_ca_cert = global_configuration.ssl_ca_cert
        configuration.cert_file = global_configuration.cert_file
        configuration.key_file = global_configuration.key_file
        if global_configuration.proxy is not None:
            configuration.proxy = global_configuration.proxy
            configuration.proxy_headers = global_configuration.proxy_headers
        if global_configuration.api_endpoint is not None:
            configuration.host = global_configuration.api_endpoint

        api_client = ApiClient(configuration=configuration)
        api_client.configuration.logger = self.logger
        api_client.configuration.logger_stream_handler = self.logger.handlers[0]
        api_client.user_agent = USER_AGENT

        # Apply caller-supplied headers first so SDK-managed auth headers
        # always take precedence and cannot be clobbered.
        for name, value in global_configuration.custom_headers.items():
            api_client.set_default_header(name, value)

        if global_configuration.api_key is not None:
            api_client.set_default_header(HEADER_API_KEY, global_configuration.api_key)
        if global_configuration.api_token is not None:
            api_client.set_default_header(HEADER_AUTH_TOKEN, BEARER + global_configuration.api_token)

        self.logger.debug(f"event={self.create_api_client.__name__} action=new_api_client_created")
        return api_client


class ScanApiBase(ApiBase):
    def __init__(self):
        super().__init__()
        self.__scan_api = ScansApi(self.api_client)

    @property
    def scan_api(self):
        return self.__scan_api
