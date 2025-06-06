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

import aiohttp
from singleton_decorator import singleton

from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import (
    AsyncScanObject,
    AsyncScanResponse,
)
from aisecurity.generated_openapi_client.asyncio.exceptions import ApiException
from aisecurity.scan.asyncio.base import ScanApiBase


@singleton
class AsyncScanExecutor(ScanApiBase):
    def __init__(self):
        """
        Initialize the AsyncScanExecutor with the ScansApi client.
        """
        super().__init__()

    async def async_request(self, scan_objects: list[AsyncScanObject]) -> AsyncScanResponse:
        """
        Make an asynchronous scan request to the API.

        Args:
            scan_objects (list[AsyncScanObject]): A list of AsyncScanObjects to be scanned.

        Returns:
            AsyncScanResponse: The response from the asynchronous scan request.

        Raises:
            Exception: If there's an error during the API call.
        """
        if len(scan_objects) == 0:
            error_msg = "No scan objects are provided."
            self.logger.error(f"event={self.async_request.__name__} error={error_msg}")
            raise AISecSDKException(error_msg, ErrorType.USER_REQUEST_PAYLOAD_ERROR)

        try:
            response = await self.scan_api.scan_async_request(async_scan_object=scan_objects)
            return response
        except ApiException as e:
            """
                Handle API exceptions that may occur during the API call.
            """
            self.logger.error(f"event={self.async_request.__name__} error={e}")
            raise AISecSDKException(str(e), ErrorType.SERVER_SIDE_ERROR)
        except aiohttp.ClientError as e:
            """
                A catch-all for other client-side exceptions that may occur during the API call.Ex ClientConnectionError,ClientTimeoutError,ClientResponseError,ClientPayloadError
            """
            self.logger.error(f"event={self.async_request.__name__} error={e}")
            raise AISecSDKException(str(e), ErrorType.CLIENT_SIDE_ERROR)
        except Exception as e:
            self.logger.error(f"event={self.async_request.__name__} error={e!r}")
            raise
