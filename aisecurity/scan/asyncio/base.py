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

import aiohttp_retry

from aisecurity import global_configuration
from aisecurity.constants.base import (
    HEADER_API_KEY,
    HTTP_FORCE_RETRY_STATUS_CODES,
    MAX_CONNECTION_POOL_SIZE,
    USER_AGENT,
    HEADER_AUTH_TOKEN,
    BEARER,
)
from aisecurity.generated_openapi_client.asyncio.api import ScansApi
from aisecurity.generated_openapi_client.asyncio.api_client import ApiClient
from aisecurity.generated_openapi_client.asyncio.configuration import Configuration
from aisecurity.logger import BaseLogger


class ApiBase(BaseLogger):
    def __init__(self):
        super().__init__()
        self.__api_client = self.create_api_client()

    @property
    def api_client(self):
        return self.__api_client

    async def close(self):
        await self.__api_client.close()
        self.logger.debug(f"event={self.close.__name__} event=client_session_closed")

    def create_api_client(self):
        # Populate the transport configuration before ApiClient() builds the
        # aiohttp ClientSession, so the SSL context (CA bundle, client cert,
        # verification toggle) and proxy settings are applied to the connector.
        configuration = Configuration()
        configuration.connection_pool_maxsize = MAX_CONNECTION_POOL_SIZE
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
        # Wrap the SSL-configured session with retry behaviour that also
        # retries on the configured HTTP status codes.
        api_client.rest_client.retry_client = aiohttp_retry.RetryClient(
            client_session=api_client.rest_client.pool_manager,
            retry_options=aiohttp_retry.ExponentialRetry(
                attempts=global_configuration.num_retries,
                statuses=set(HTTP_FORCE_RETRY_STATUS_CODES),
            ),
        )
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
