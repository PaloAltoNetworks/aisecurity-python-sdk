"""
Traditional Python Batch (Asynchronous/Multiple) Scan Example

API Reference: https://pan.dev/ai-runtime-security/api/scan-async-request/
"""

import os
from pprint import pprint

import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.generated_openapi_client.models.async_scan_object import AsyncScanObject
from aisecurity.generated_openapi_client.models.scan_request import ScanRequest
from aisecurity.generated_openapi_client.models.scan_request_contents_inner import (
    ScanRequestContentsInner,
)

# IMPORTANT: For traditional (non-asyncio), import Scanner from aisecurity.scan.inline.scanner
from aisecurity.scan.inline.scanner import Scanner

AI_PROFILE_NAME = "YOUR_AI_PROFILE_NAME"
API_KEY = os.getenv("PANW_AI_SEC_API_KEY")

# Initialize the SDK with your API Key
aisecurity.init(api_key=API_KEY)

# Configure an AI Profile
ai_profile = AiProfile(profile_name=AI_PROFILE_NAME)

# Create a Scanner
scanner = Scanner()

req_ids = 0
# Batch (Asyncronous) Scan supports up to 5 Scan Request Objects
async_scan_objects = [
    AsyncScanObject(
        req_id=(req_ids := req_ids + 1),
        scan_req=ScanRequest(
            ai_profile=ai_profile,
            contents=[
                ScanRequestContentsInner(
                    prompt="First Questionable User Prompt Text",
                    response="First Questionable Model Response Text",
                )
            ],
        ),
    ),
    AsyncScanObject(
        req_id=(req_ids := req_ids + 1),
        scan_req=ScanRequest(
            ai_profile=ai_profile,
            contents=[
                ScanRequestContentsInner(
                    prompt="Second Questionable User Prompt Text",
                    response="Second Questionable Model Response Text",
                )
            ],
        ),
    ),
]

response = scanner.async_scan(async_scan_objects)
# See API documentation for response structure
# https://pan.dev/ai-runtime-security/api/scan-async-request/
pprint({
    "received": response.received,
    "scan_id": response.scan_id,
    "report_id": response.report_id,
})
