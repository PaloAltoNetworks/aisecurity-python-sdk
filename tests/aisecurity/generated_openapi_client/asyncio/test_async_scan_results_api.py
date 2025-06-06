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
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from aisecurity.generated_openapi_client import (
    PromptDetected,
    ResponseDetected,
    ScanIdResult,
    ScanResponse,
)
from aisecurity.generated_openapi_client.asyncio.api_client import ApiClient
from aisecurity.generated_openapi_client.asyncio.configuration import Configuration


class TestScanResultsApi(unittest.IsolatedAsyncioTestCase):
    """ScanResultsApi unit tests stubs"""

    @patch(
        "aisecurity.generated_openapi_client.asyncio.api.scan_results_api.ScanResultsApi",
        new_callable=AsyncMock,
    )
    async def asyncSetUp(self, MockScanResultsApi) -> None:
        mock_api_client = AsyncMock(spec=ApiClient)
        mock_configuration = AsyncMock(spec=Configuration)
        mock_configuration.host = "https://mock.api.host"
        mock_api_client.configuration = mock_configuration

        # Create a mock for default_headers as a dictionary
        mock_api_client.default_headers = {"x-pan-token": "mock-api-key"}
        self.mock_scans_result_api = MockScanResultsApi.return_value
        self.mock_scans_result_api.api_client = mock_api_client

    async def asyncTearDown(self) -> None:
        await self.mock_scans_result_api.api_client.close()
        await self.mock_scans_result_api.close()

    async def test_get_scan_results_by_scan_ids_concurrent(self) -> None:
        """Test case for get_scan_results_by_scan_ids with concurrent tasks"""

        def create_mock_scan_response(scan_id):
            return ScanResponse(
                report_id=f"REP{scan_id}",
                scan_id=scan_id,
                tr_id=f"TR{scan_id}",
                profile_id="PROF789",
                profile_name="Standard Security Profile",
                category="benign",
                action="allow",
                prompt_detected=PromptDetected(url_cats=True, dlp=False, injection=False),
                response_detected=ResponseDetected(url_cats=False, dlp=False),
                created_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )

        def create_mock_scan_id_result(req_id, scan_id):
            return ScanIdResult(
                req_id=req_id,
                status="complete",
                scan_id=scan_id,
                result=create_mock_scan_response(scan_id),
            )

        # Create mock responses for different scan IDs
        mock_responses = [
            [create_mock_scan_id_result(100, "SCAN987654321")],
            [create_mock_scan_id_result(101, "SCAN987654322")],
            [create_mock_scan_id_result(102, "SCAN987654323")],
        ]

        self.mock_scans_result_api.get_scan_results_by_scan_ids.side_effect = mock_responses

        # Define concurrent tasks
        async def fetch_scan_result(scan_id):
            return await self.mock_scans_result_api.get_scan_results_by_scan_ids(scan_ids=[scan_id])

        # Run concurrent tasks
        scan_ids = ["SCAN987654321", "SCAN987654322", "SCAN987654323"]
        results = await asyncio.gather(*[fetch_scan_result(scan_id) for scan_id in scan_ids])

        # print ("the result is ",results)

        # Assert results
        self.assertEqual(len(results), 3)

        expected_scan_ids = set(scan_ids)
        received_scan_ids = set()

        for result in results:
            self.assertEqual(len(result), 1)
            scan_id_result = result[0]
            self.assertIsInstance(scan_id_result, ScanIdResult)
            self.assertEqual(scan_id_result.status, "complete")
            self.assertIsInstance(scan_id_result.result, ScanResponse)

            received_scan_ids.add(scan_id_result.scan_id)

            # Basic checks on ScanResponse
            self.assertEqual(scan_id_result.result.report_id, f"REP{scan_id_result.scan_id}")
            self.assertEqual(scan_id_result.result.profile_name, "Standard Security Profile")
            self.assertEqual(scan_id_result.result.category, "benign")

        # Verify all expected scan_ids were received
        self.assertEqual(expected_scan_ids, received_scan_ids)


if __name__ == "__main__":
    unittest.main()
