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
from unittest.mock import AsyncMock, patch

from aisecurity.generated_openapi_client import (
    DetectionServiceResultObject,
    DlpReportObject,
    DSDetailResultObject,
    ThreatScanReportObject,
    UrlfEntryObject,
)
from aisecurity.generated_openapi_client.asyncio.api_client import ApiClient
from aisecurity.generated_openapi_client.asyncio.configuration import Configuration


class TestScanReportsApi(unittest.IsolatedAsyncioTestCase):
    """ScanReportsApi unit tests stubs"""

    @patch(
        "aisecurity.generated_openapi_client.asyncio.api.scan_reports_api.ScanReportsApi",
        new_callable=AsyncMock,
    )
    async def asyncSetUp(self, MockScanReportsApi) -> None:
        mock_api_client = AsyncMock(spec=ApiClient)
        mock_configuration = AsyncMock(spec=Configuration)
        mock_configuration.host = "https://mock.api.host"
        mock_api_client.configuration = mock_configuration

        # Create a mock for default_headers as a dictionary
        mock_api_client.default_headers = {"x-pan-token": "mock-api-key"}
        self.mock_scans_reports_api = MockScanReportsApi.return_value
        self.mock_scans_reports_api.api_client = mock_api_client

    async def asyncTearDown(self) -> None:
        await self.mock_scans_reports_api.api_client.close()
        await self.mock_scans_reports_api.close()

    async def test_get_threat_scan_reports(self) -> None:
        """Test case for get_threat_scan_reports

        Retrieve Threat Scan Reports by Report IDs
        """
        mock_detection_service_objects = [
            DetectionServiceResultObject(
                data_type="prompt",
                detection_service="urlf",
                verdict="malicious",
                action="block",
                result_detail=DSDetailResultObject(
                    urlf_report=[
                        UrlfEntryObject(
                            url="http://malicious-example.com",
                            risk_level="high",
                            categories=["malware", "phishing"],
                        ),
                        UrlfEntryObject(
                            url="http://suspicious-site.com",
                            risk_level="medium",
                            categories=["suspicious"],
                        ),
                    ],
                    dlp_report=DlpReportObject(
                        dlp_report_id="DLP-123456",
                        dlp_profile_name="Sensitive Data Profile",
                        dlp_profile_id="PROF-789",
                        dlp_profile_version=2,
                        data_pattern_rule1_verdict="NOT MATCHED",
                        data_pattern_rule2_verdict="MATCHED",
                    ),
                ),
            )
        ]

        def create_mock_scan_report(req_id, report_id):
            return [
                ThreatScanReportObject(
                    req_id=req_id,
                    report_id=report_id,
                    scan_id="SCAN987654321",
                    transaction_id="TRANSACTION_1234",
                    detection_results=mock_detection_service_objects,
                )
            ]

        mock_responses = [
            create_mock_scan_report(100, "REPORT_ID_1234"),
            create_mock_scan_report(101, "REPORT_ID_1235"),
            create_mock_scan_report(102, "REPORT_ID_1236"),
        ]
        self.mock_scans_reports_api.get_threat_scan_reports.side_effect = mock_responses

        async def fetch_scan_report(report_id):
            return await self.mock_scans_reports_api.get_threat_scan_reports(report_ids=[report_id])

        report_ids = ["REPORT_ID_1234", "REPORT_ID_1235", "REPORT_ID_1236"]
        results = await asyncio.gather(*[fetch_scan_report(report_id) for report_id in report_ids])

        self.assertEqual(len(results), 3)

        expected_report_ids = set(report_ids)
        received_report_ids = set()

        for result in results:
            self.assertEqual(len(result), 1)  # Each result should be a list with one item
            report = result[0]
            self.assertIsInstance(report, ThreatScanReportObject)
            self.assertEqual(report.scan_id, "SCAN987654321")
            self.assertEqual(report.transaction_id, "TRANSACTION_1234")

            received_report_ids.add(report.report_id)

            self.assertEqual(len(report.detection_results), 1)
            detection = report.detection_results[0]
            self.assertIsInstance(detection, DetectionServiceResultObject)
            self.assertEqual(detection.data_type, "prompt")
            self.assertEqual(detection.detection_service, "urlf")

        # Verify all expected report_ids were received
        self.assertEqual(expected_report_ids, received_report_ids)


if __name__ == "__main__":
    unittest.main()
