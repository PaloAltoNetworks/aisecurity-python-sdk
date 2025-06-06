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
import asyncio
from typing import Optional

from aisecurity.generated_openapi_client import (
    AiProfile,
    AsyncScanObject,
    AsyncScanResponse,
    ScanIdResult,
    ScanResponse,
    ThreatScanReportObject,
)
from aisecurity.generated_openapi_client.models.metadata import Metadata
from aisecurity.logger import BaseLogger
from aisecurity.scan.asyncio.async_scan_executor import AsyncScanExecutor
from aisecurity.scan.asyncio.query_by_report_ids import QueryByReportIds
from aisecurity.scan.asyncio.query_by_scan_ids import QueryByScanIds
from aisecurity.scan.asyncio.scan_executor import ScanExecutor
from aisecurity.scan.models.content import Content


class Scanner(BaseLogger):
    """
    A class to handle various scanning operations and queries.
    """

    def __init__(self):
        """
        Initialize the Scanner object with default values and logger setup.
        """
        super().__init__()
        self._scan_executor = None
        self._async_scan_executor = None
        self._query_scan_by_scan_ids = None
        self._query_by_report_ids = None

    async def sync_scan(
        self,
        ai_profile: AiProfile,
        content: Content,
        tr_id: Optional[str] = None,
        metadata: Optional[Metadata] = None,
    ) -> ScanResponse:
        """
        Perform a synchronous (inline) scan.

        Args:
            ai_profile (AiProfile): The AI profile to use for the scan.
            content (Content): The content to be scanned.
            tr_id (str): Optionally Provide any unique identifier string for correlating the prompt and \
                        response transactions. This is an optional field. The tr_id value received for scan request is \
                        returned in the scan response along with the scan ID
            metadata (Metadata): Optionally send the app_name, app_user, and ai_model in the metadata

        Returns:
            scan response and of the operation.
        """
        if self._scan_executor is None:
            self._scan_executor = ScanExecutor()

        scan_response = await self._scan_executor.sync_request(
            ai_profile=ai_profile, content=content, tr_id=tr_id, metadata=metadata
        )

        self.logger.info(f"event={self.sync_scan.__name__} ")
        self.logger.debug(f"event={self.sync_scan.__name__} ai_profile={ai_profile!r} ")

        return scan_response

    async def async_scan(self, async_scan_objects: list[AsyncScanObject]) -> AsyncScanResponse:
        """
        Perform an asynchronous scan.

        Args:
            async_scan_objects (list[AsyncScanObject]): A list of AsyncScanObject instances to be scanned.

        Returns:
            Response containing the AsyncScanResponse object
        """
        if self._async_scan_executor is None:
            self._async_scan_executor = AsyncScanExecutor()

        async_scan_response = await self._async_scan_executor.async_request(
            scan_objects=async_scan_objects,
        )

        self.logger.info(f"event={self.async_scan.__name__} ")

        return async_scan_response

    async def query_by_scan_ids(self, scan_ids: list[str]) -> list[ScanIdResult]:
        """
        Query scan results by scan IDs.

        Args:
            scan_ids (list[str]): A list of scan IDs to query.

        Returns:
            List of scan ID's responses.
        """
        if self._query_scan_by_scan_ids is None:
            self._query_scan_by_scan_ids = QueryByScanIds()

        scan_id_responses = await self._query_scan_by_scan_ids.get_scan_results(scan_ids=scan_ids)

        self.logger.info(f"event={self.query_by_report_ids.__name__} ")
        self.logger.debug(f"event={self.query_by_report_ids.__name__} scan_ids={scan_ids!r} ")

        return scan_id_responses

    async def query_by_report_ids(self, report_ids: list[str]) -> list[ThreatScanReportObject]:
        """
        Query scan results by report IDs.

        Args:
            report_ids (list[str]): A list of report IDs to query.

        Returns:
           List of ThreatReportObjects.
        """
        if self._query_by_report_ids is None:
            self._query_by_report_ids = QueryByReportIds()

        scan_id_responses = await self._query_by_report_ids.get_threat_objects(report_ids=report_ids)

        self.logger.info(f"event={self.query_by_report_ids.__name__} ")
        self.logger.debug(f"event={self.query_by_report_ids.__name__} report_ids={report_ids!r} ")

        return scan_id_responses

    async def close(self) -> None:
        """
        Closes all Open Asyncio Connection Pools in underlying HTTP client libraries.

        Use this function to avoid leaking asyncio tasks, which may result in a warning emitted to stderr.
        """
        executors = [
            self._scan_executor,
            self._async_scan_executor,
            self._query_scan_by_scan_ids,
            self._query_by_report_ids,
        ]
        tasks = []
        for executor in executors:
            if executor is not None:
                self.logger.debug(f"Closing connection pool for {executor.__class__.__name__}")
                tasks.append(executor.close())
        if tasks:
            await asyncio.gather(*tasks)
            self.logger.debug(f"Closed {len(tasks)} asyncio connection pools")
