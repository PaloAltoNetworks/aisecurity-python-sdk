"""
Retrieve Threat Scan Reports by Report IDs

API Reference: https://pan.dev/ai-runtime-security/api/get-threat-scan-reports/
"""

import aisecurity

# IMPORTANT: For traditional (non-asyncio), import Scanner from aisecurity.scan.inline.scanner
from aisecurity.scan.inline.scanner import Scanner

aisecurity.init()

scanner = Scanner()

# See API documentation for response structure
# https://pan.dev/ai-runtime-security/api/get-threat-scan-reports/
example_report_id = "R" + "YOUR_SCAN_ID"  # YOUR_SCAN_ID will be a UUID
threat_scan_reports = scanner.query_by_report_ids(report_ids=[example_report_id])
