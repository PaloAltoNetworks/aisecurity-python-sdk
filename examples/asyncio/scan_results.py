"""
Asyncio Python Retrieve Scan Results by ScanIDs Example

API Reference: https://pan.dev/ai-runtime-security/api/get-scan-results-by-scan-i-ds/
"""

import asyncio
from pprint import pprint

import aisecurity

# IMPORTANT: For asyncio, import Scanner from aisecurity.scan.asyncio.scanner
from aisecurity.scan.asyncio.scanner import Scanner

aisecurity.init()

scanner = Scanner()


async def main():
    try:
        # See API documentation for response structure
        # https://pan.dev/ai-runtime-security/api/get-scan-results-by-scan-i-ds/
        example_scan_id = "YOUR_SCAN_ID"  # This will be a UUID
        scan_results = await scanner.query_by_scan_ids(scan_ids=[example_scan_id])
        pprint(scan_results)
    finally:
        # Important: close the connection pool after use to avoid leaking threads
        await scanner.close()


if __name__ == "__main__":
    asyncio.run(main())
