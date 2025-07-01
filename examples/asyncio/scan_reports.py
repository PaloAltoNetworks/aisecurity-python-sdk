"""

Python Asyncio Retrieve Threat Scan Reports by Report IDs Example

API Reference: https://pan.dev/ai-runtime-security/api/get-threat-scan-reports/
"""

import asyncio
from pprint import pprint

import aisecurity

# IMPORTANT: For asyncio, import Scanner from aisecurity.scan.asyncio.scanner
from aisecurity.scan.asyncio.scanner import Scanner

aisecurity.init()

scanner = Scanner()


async def main():
    # See API documentation for response structur
    # https://pan.dev/ai-runtime-security/api/get-threat-scan-reports/
    try:
        example_report_id = "R" + "YOUR_SCAN_ID"  # YOUR_SCAN_ID will be a UUID
        threat_scan_reports = await scanner.query_by_report_ids(report_ids=[example_report_id])
        pprint(threat_scan_reports)
    finally:
        # Important: close the connection pool after use to avoid leaking threads
        await scanner.close()


if __name__ == "__main__":
    asyncio.run(main())
