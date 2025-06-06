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

from urllib3 import poolmanager
from urllib3.util import Retry

from aisecurity import global_configuration
from aisecurity.constants.base import (
    HEADER_API_KEY,
    HTTP_FORCE_RETRY_STATUS_CODES,
    USER_AGENT,
)
from aisecurity.generated_openapi_client.urllib3.api.scans_api import ScansApi
from aisecurity.generated_openapi_client.urllib3.api_client import ApiClient
from aisecurity.logger import BaseLogger


class ApiBase(BaseLogger):
    def __init__(self):
        super().__init__()
        self.__api_client = self.create_api_client()

    @property
    def api_client(self):
        return self.__api_client

    def create_api_client(self):
        api_client = ApiClient()
        api_client.configuration.logger = self.logger
        api_client.configuration.logger_stream_handler = self.logger.handlers[0]
        api_client.user_agent = USER_AGENT

        api_client.rest_client.pool_manager = poolmanager.PoolManager(
            retries=Retry(
                total=global_configuration.num_retries,
                status_forcelist=HTTP_FORCE_RETRY_STATUS_CODES,
            ),
        )

        if global_configuration.api_endpoint is not None:
            api_client.configuration.host = global_configuration.api_endpoint

        if global_configuration.api_key is not None:
            api_client.set_default_header(HEADER_API_KEY, global_configuration.api_key)

        self.logger.debug(f"event={self.create_api_client.__name__} action=new_api_client_created")
        return api_client


class ScanApiBase(ApiBase):
    def __init__(self):
        super().__init__()
        self.__scan_api = ScansApi(self.api_client)

    @property
    def scan_api(self):
        return self.__scan_api
