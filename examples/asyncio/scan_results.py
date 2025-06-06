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
