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

from aisecurity.constants.base import (
    MAX_NUMBER_OF_SCAN_IDS,
    MAX_SCAN_ID_STR_LENGTH,
)
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import ScanIdResult
from aisecurity.generated_openapi_client.asyncio.api import ScanResultsApi
from aisecurity.generated_openapi_client.asyncio.exceptions import ApiException
from aisecurity.scan.asyncio.base import ApiBase
from aisecurity.utils import Utils


@singleton
class QueryByScanIds(ApiBase):
    def __init__(self):
        """
        Initialize the QueryByScanIds instance with the ScanResultsApi.
        """
        super().__init__()
        self.__api = ScanResultsApi(api_client=self.api_client)

    async def get_scan_results(self, scan_ids: list[str]) -> list[ScanIdResult]:
        """
        Retrieve scan results for the given scan IDs.

        Args:
            scan_ids (list[str]): A list of scan IDs to query.

        Returns:
            list[ScanIdResult]: A list of ScanIdResult objects containing the scan results.

        Raises:
            ValueError: If any scan_id exceeds the maximum allowed length.
        """
        if not scan_ids:
            error_msg = "At least one scan ID must be provided"
            self.logger.error(f"event={self.get_scan_results.__name__} error={error_msg}")
            raise AISecSDKException(error_msg, ErrorType.USER_REQUEST_PAYLOAD_ERROR)

        if len(scan_ids) > MAX_NUMBER_OF_SCAN_IDS:
            error_msg = f"Number of report IDs exceeds the maximum allowed ({MAX_NUMBER_OF_SCAN_IDS})."
            self.logger.error(f"event={self.get_scan_results.__name__} error={error_msg}")
            raise AISecSDKException(
                error_msg,
                ErrorType.USER_REQUEST_PAYLOAD_ERROR,
            )

        # Validate scan_id lengths
        for scan_id in scan_ids:
            if scan_id is None or len(scan_id) == 0:
                raise AISecSDKException(
                    "Scan Id can't be None or empty",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
            elif len(scan_id) > MAX_SCAN_ID_STR_LENGTH:
                error_msg = (
                    f"'{scan_id}' Scan ID exceeds the maximum allowed length of {MAX_SCAN_ID_STR_LENGTH} characters."
                )
                self.logger.error(f"event={self.get_scan_results.__name__} error={error_msg}")
                raise AISecSDKException(
                    error_msg,
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
            elif not (Utils.is_valid_uuid(scan_id)):
                error_msg = f"'{scan_id}' Scan ID format must be in UUID format."
                self.logger.error(f"event={self.get_scan_results.__name__} error={error_msg}")
                raise AISecSDKException(error_msg, ErrorType.USER_REQUEST_PAYLOAD_ERROR)

        try:
            response = await self.__api.get_scan_results_by_scan_ids(scan_ids=scan_ids)
            return response
        except ApiException as e:
            """
                Handle API exceptions that may occur during the API call. Ex Invalid input data,Authentication errors,Authorization errors,Resource not found
            """
            self.logger.error(f"event={self.get_scan_results.__name__} error={e}")
            raise AISecSDKException(str(e), ErrorType.SERVER_SIDE_ERROR)
        except aiohttp.ClientError as e:
            """
                A catch-all for other client-side exceptions that may occur during the API call.Ex ClientConnectionError,ClientTimeoutError,ClientResponseError,ClientPayloadError
            """
            self.logger.error(f"event={self.get_scan_results.__name__} error={e}")
            raise AISecSDKException(str(e), ErrorType.CLIENT_SIDE_ERROR)
        except Exception as e:
            self.logger.error(f"event={self.get_scan_results.__name__} error={e!r}")
            raise AISecSDKException(str(e))
