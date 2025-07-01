"""
Traditional Python Inline (Synchronous/Single) Scan Example

API Reference: https://pan.dev/ai-runtime-security/api/scan-sync-request/
"""

import os
from pprint import pprint

import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile

# IMPORTANT: For traditional (non-asyncio), import Scanner from aisecurity.scan.inline.scanner
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

AI_PROFILE_NAME = "YOUR_AI_PROFILE_NAME"
API_KEY = os.getenv("PANW_AI_SEC_API_KEY")

# Initialize the SDK with your API Key
aisecurity.init(api_key=API_KEY)

# Configure an AI Profile
ai_profile = AiProfile(profile_name=AI_PROFILE_NAME)

# Create a Scanner
scanner = Scanner()

scan_response = scanner.sync_scan(
    ai_profile=ai_profile,
    content=Content(
        prompt="Questionable User Prompt Text",
        response="Questionable Model Response Text",
    ),
)
# See API documentation for response structure
# https://pan.dev/ai-runtime-security/api/scan-sync-request/
pprint(scan_response)
