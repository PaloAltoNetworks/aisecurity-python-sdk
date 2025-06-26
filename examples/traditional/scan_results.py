"""
Traditional Python Retrieve Scan Results by ScanIDs Example

API Reference: https://pan.dev/ai-runtime-security/api/get-scan-results-by-scan-i-ds/
"""

import aisecurity

# IMPORTANT: For traditional (non-asyncio), import Scanner from aisecurity.scan.inline.scanner
from aisecurity.scan.inline.scanner import Scanner

aisecurity.init()

scanner = Scanner()

# See API documentation for response structure
# https://pan.dev/ai-runtime-security/api/get-scan-results-by-scan-i-ds/
example_scan_id = "YOUR_SCAN_ID"  # This will be a UUID
scan_by_ids_response = scanner.query_by_scan_ids(scan_ids=[example_scan_id])
