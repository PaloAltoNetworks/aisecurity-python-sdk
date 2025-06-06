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

from aisecurity.constants.base import MAX_NUMBER_OF_REPORT_IDS, MAX_REPORT_ID_STR_LENGTH
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import ThreatScanReportObject
from aisecurity.generated_openapi_client.asyncio.api import ScanReportsApi
from aisecurity.generated_openapi_client.asyncio.exceptions import ApiException
from aisecurity.scan.asyncio.base import ApiBase


@singleton
class QueryByReportIds(ApiBase):
    """
    A singleton class for querying threat scan reports by report IDs.
    """

    def __init__(self):
        """
        Initialize the QueryByReportId instance with the ScanReportsApi.

        This method sets up the API client for making requests to the ScanReportsApi.
        """
        super().__init__()
        self.__api = ScanReportsApi(api_client=self.api_client)

    async def get_threat_objects(self, report_ids: list[str]) -> list[ThreatScanReportObject]:
        """
        Retrieve threat scan reports for the given report IDs.

        This method queries the ScanReportsApi to fetch threat scan reports
        corresponding to the provided report IDs.

        Args:
            report_ids (list[str]): A list of report IDs to query.

        Returns:
            list[ThreatScanReportObject]: A list of threat scan report objects
                corresponding to the provided report IDs.

        Raises:
            ValueError: If any report ID exceeds the maximum allowed length.
        """
        if not report_ids:
            error_msg = "At least one report ID must be provided"
            self.logger.error(f"event={self.get_threat_objects.__name__} error={error_msg}")
            raise AISecSDKException(error_msg, ErrorType.USER_REQUEST_PAYLOAD_ERROR)

        if len(report_ids) > MAX_NUMBER_OF_REPORT_IDS:
            error_msg = f"The number of report_ids should not exceed {MAX_NUMBER_OF_REPORT_IDS}."
            self.logger.error(f"event={self.get_threat_objects.__name__} error={error_msg}")
            raise AISecSDKException(
                error_msg,
                ErrorType.USER_REQUEST_PAYLOAD_ERROR,
            )

        # Validate report ID lengths
        for report_id in report_ids:
            if report_id is None or len(report_id) == 0:
                raise AISecSDKException(
                    "Report ID Can't be None or Empty",
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )
            elif len(report_id) > MAX_REPORT_ID_STR_LENGTH:
                error_msg = (
                    f"Report ID '{report_id}' exceeds the maximum allowed length of "
                    f"{MAX_REPORT_ID_STR_LENGTH} characters."
                )
                self.logger.error(f"event={self.get_threat_objects.__name__} error={error_msg}")
                raise AISecSDKException(
                    error_msg,
                    ErrorType.USER_REQUEST_PAYLOAD_ERROR,
                )

        try:
            result = await self.__api.get_threat_scan_reports(report_ids=report_ids)
            return result
        except ApiException as e:
            """
                Handle API exceptions that may occur during the API call. Ex Invalid input data,Authentication errors,Authorization errors,Resource not found
            """
            self.logger.error(f"event={self.get_threat_objects.__name__} error={e}")
            raise AISecSDKException(str(e), ErrorType.SERVER_SIDE_ERROR)
        except aiohttp.ClientError as e:
            """
                A catch-all for other client-side exceptions that may occur during the API call.Ex ClientConnectionError,ClientTimeoutError,ClientResponseError,ClientPayloadError
            """
            self.logger.error(f"event={self.get_threat_objects.__name__} error={e}")
            raise AISecSDKException(str(e), ErrorType.CLIENT_SIDE_ERROR)
        except Exception as e:
            self.logger.error(f"event={self.get_threat_objects.__name__} error={e!r}")
            raise AISecSDKException(str(e))
