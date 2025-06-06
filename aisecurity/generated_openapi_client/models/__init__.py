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

# flake8: noqa
"""
AISec API service

OpenAPI Specification for the AI Runtime Security API service

The version of the OpenAPI document: 0.0.0
Generated by OpenAPI Generator (https://openapi-generator.tech)

Do not edit the class manually.
"""  # noqa: E501

# import models into model package
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.generated_openapi_client.models.async_scan_object import AsyncScanObject
from aisecurity.generated_openapi_client.models.async_scan_response import (
    AsyncScanResponse,
)
from aisecurity.generated_openapi_client.models.ds_detail_result_object import (
    DSDetailResultObject,
)
from aisecurity.generated_openapi_client.models.detection_service_result_object import (
    DetectionServiceResultObject,
)
from aisecurity.generated_openapi_client.models.dlp_report_object import DlpReportObject
from aisecurity.generated_openapi_client.models.error import Error
from aisecurity.generated_openapi_client.models.metadata import Metadata
from aisecurity.generated_openapi_client.models.prompt_detected import PromptDetected
from aisecurity.generated_openapi_client.models.response_detected import (
    ResponseDetected,
)
from aisecurity.generated_openapi_client.models.scan_id_result import ScanIdResult
from aisecurity.generated_openapi_client.models.scan_request import ScanRequest
from aisecurity.generated_openapi_client.models.scan_request_contents_inner import (
    ScanRequestContentsInner,
)
from aisecurity.generated_openapi_client.models.scan_response import ScanResponse
from aisecurity.generated_openapi_client.models.scan_sync_request_default_response import (
    ScanSyncRequestDefaultResponse,
)
from aisecurity.generated_openapi_client.models.threat_scan_report_object import (
    ThreatScanReportObject,
)
from aisecurity.generated_openapi_client.models.urlf_entry_object import UrlfEntryObject
