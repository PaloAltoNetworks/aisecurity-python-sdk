Palo Alto Networks Prisma AIRS Scan API Python SDK
=============================================

This Python SDK provides convenient access to the
Palo Alto Networks AI Runtime Security: API Intercept
for Python applications. This SDK includes type
definitions for all request params and response fields and offers both
synchronous and asynchronous (asyncio) operations.

<!--TOC-->

- [API Documentation](#api-documentation)
- [Installation](#installation)
- [SDK Configuration](#sdk-configuration)
  - [API Key](#api-key)
  - [AI Profile](#ai-profile)
- [Example: SDK Configuration](#example-sdk-configuration)
  - [Using AI Profile Name](#using-ai-profile-name)
  - [Using AI Profile ID](#using-ai-profile-id)
- [Examples: Traditional Python (non-asyncio)](#examples-traditional-python-non-asyncio)
  - [Inline (Synchronous) Scan Example](#inline-synchronous-scan-example)
  - [Batch (Asynchronous) Scan Example](#batch-asynchronous-scan-example)
  - [Scan Results Example](#scan-results-example)
  - [Scan Reports Example](#scan-reports-example)
- [Examples: Concurrent Python (asyncio)](#examples-concurrent-python-asyncio)
  - [Inline (Synchronous) Scan Example (asyncio)](#inline-synchronous-scan-example-asyncio)
  - [Batch (Asynchronous) Scan Example (asyncio)](#batch-asynchronous-scan-example-asyncio)
  - [Scan Results Example (asyncio)](#scan-results-example-asyncio)
  - [Scan Reports Example (asyncio)](#scan-reports-example-asyncio)
- [Examples: Model Context Protocol](#examples-model-context-protocol)
  - [Model Context Protocol Server Example](#model-context-protocol-server-example)
- [Error Handling & Exceptions](#error-handling--exceptions)
- [Compatability Policy](#compatability-policy)
- [Legal](#legal)

<!--TOC-->


<a id="api-documentation" aria-hidden="true" href="#api-documentation">

# API Documentation

</a>

The reference API documentation for Palo Alto Networks AI Runtime Security:
API Intercept can be found at [https://pan.dev/ai-runtime-security/scan/api/](https://pan.dev/ai-runtime-security/scan/api/)

<a id="installation" href="#installation">

# Installation

</a>

```sh
# Create and activate a virtual environment
python3 -m venv --prompt ${PWD##*/} .venv && source .venv/bin/activate

# Install most recent release version of aisecurity package
python3 -m pip install "pan-aisecurity"
```
<a id="sdk-configuration" href="#sdk-configuration">

# SDK Configuration

</a>

The `aisecurity.init()` function accepts the following _**optional**_ parameters:

- `api_key` (optional): Provide your API key through configuration or an environment variable.
  - If `api_key` is not set, the environment variable `PANW_AI_SEC_API_KEY` will be used, if available.
- `num_retries` (optional): Default value is 5.

<a id="api-key" href="#api-key">

## API Key

</a>

There are two ways to specify your API key:

1. Using an environment variable:

```sh
export PANW_AI_SEC_API_KEY=YOUR_API_KEY
```

2. Specify your API key in `aisecurity.init()` with the `api_key` parameter:

```python
api_key = get_api_key_from_somewhere() # Fetch from Vault, Secrets Manager, etc.
aisecurity.init(api_key=api_key)
```

<a id="ai-profile" href="#ai-profile">

## AI Profile

</a>

You must provide ONE of: `profile_name` or `profile_id`

```python
ai_profile = AiProfile(profile_id="YOUR_AI_PROFILE_ID")
```

or

```python
ai_profile = AiProfile(profile_name="YOUR_AI_PROFILE_NAME")
```

<a id="example-sdk-configuration" href="#example-sdk-configuration">

# Example: SDK Configuration

</a>

<a id="using-ai-profile-name" href="#using-ai-profile-name">

## Using AI Profile Name

</a>

```python
import aisecurity
AI_PROFILE_NAME = "YOUR_AI_PROFILE_NAME"
API_KEY = os.getenv("PANW_AI_SEC_API_KEY")

aisecurity.init(api_key=API_KEY)
ai_profile = AiProfile(profile_name=AI_PROFILE_NAME)
```

<a id="using-ai-profile-id" href="#using-ai-profile-id">

## Using AI Profile ID

</a>

```python
import aisecurity
AI_PROFILE_ID = "YOUR_AI_PROFILE_ID"
API_KEY = os.getenv("PANW_AI_SEC_API_KEY")

aisecurity.init(api_key=API_KEY)
ai_profile = AiProfile(profile_id=AI_PROFILE_ID)
```

<a id="examples-traditional-python-non-asyncio" href="#examples-traditional-python-non-asyncio">

# Examples: Traditional Python (non-asyncio)

</a>

**Important**: You must properly configure an API Key and AI Profile ID or Name
before using the SDK examples.

<a id="inline-synchronous-scan-example" href="#inline-synchronous-scan-example">

## Inline (Synchronous) Scan Example

</a>

API Reference: https://pan.dev/ai-runtime-security/api/scan-sync-request/

<!-- source: examples/traditional/inline_sync_scan.py -->

```python

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
pprint(scan_response)
```

<a id="batch-asynchronous-scan-example" href="#batch-asynchronous-scan-example">

## Batch (Asynchronous) Scan Example

</a>

API Reference: https://pan.dev/ai-runtime-security/api/scan-async-request/

<!-- source: examples/traditional/batch_async_scan.py -->

```python
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
```

<a id="scan-results-example" href="#scan-results-example">

## Scan Results Example

</a>

API Reference: https://pan.dev/ai-runtime-security/api/get-scan-results-by-scan-i-ds/

<!-- source: examples/traditional/scan_results.py -->

```python

import aisecurity

# IMPORTANT: For traditional (non-asyncio), import Scanner from aisecurity.scan.inline.scanner
from aisecurity.scan.inline.scanner import Scanner

aisecurity.init()

scanner = Scanner()

# See API documentation for response structure
# https://pan.dev/ai-runtime-security/api/get-scan-results-by-scan-i-ds/
example_scan_id = "020e7c31-0000-4e0d-a2a6-215a0d5c56d9"
scan_by_ids_response = scanner.query_by_scan_ids(scan_ids=[example_scan_id])
```

<a id="scan-reports-example" href="#scan-reports-example">

## Scan Reports Example

</a>

API Reference: https://pan.dev/ai-runtime-security/api/get-threat-scan-reports/

<!-- source: examples/traditional/scan_reports.py -->

```python
import aisecurity

# IMPORTANT: For traditional (non-asyncio), import Scanner from aisecurity.scan.inline.scanner
from aisecurity.scan.inline.scanner import Scanner

aisecurity.init()

scanner = Scanner()

# See API documentation for response structure
# https://pan.dev/ai-runtime-security/api/get-threat-scan-reports/
example_report_id = "020e7c31-0000-4e0d-a2a6-215a0d5c56d9"
threat_scan_reports = scanner.query_by_report_ids(report_ids=[example_report_id])
```

<a id="examples-concurrent-python-asyncio" href="#examples-concurrent-python-asyncio">

# Examples: Concurrent Python (asyncio)

</a>

**Important**: You must properly configure an API Key and AI Profile ID or Name
before using the SDK examples.

<a id="inline-synchronous-scan-example-asyncio" href="#inline-synchronous-scan-example-asyncio">

## Inline (Synchronous) Scan Example (asyncio)

</a>

API Reference: https://pan.dev/ai-runtime-security/api/scan-sync-request/

<!-- source: examples/asyncio/inline_sync_scan.py -->

```python

import asyncio
import os
from pprint import pprint

import aisecurity
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile

# IMPORTANT: For asyncio, import Scanner from aisecurity.scan.asyncio.scanner
from aisecurity.scan.asyncio.scanner import Scanner
from aisecurity.scan.models.content import Content

AI_PROFILE_NAME = "YOUR_AI_PROFILE_NAME"
API_KEY = os.getenv("PANW_AI_SEC_API_KEY")

# Initialize the SDK with your API Key
aisecurity.init(api_key=API_KEY)

# Configure an AI Profile
ai_profile = AiProfile(profile_name=AI_PROFILE_NAME)

# Create a Scanner
scanner = Scanner()


async def main():
    scan_response = await scanner.sync_scan(
        ai_profile=ai_profile,
        content=Content(
            prompt="Questionable User Prompt Text",
            response="Questionable Model Response Text",
        ),
    )
    # See API documentation for response structure
    # https://pan.dev/ai-runtime-security/api/scan-sync-request/
    pprint(scan_response)


if __name__ == "__main__":
    asyncio.run(main())

```

<a id="batch-asynchronous-scan-example-asyncio" href="#batch-asynchronous-scan-example-asyncio">

## Batch (Asynchronous) Scan Example (asyncio)

</a>

API Reference: https://pan.dev/ai-runtime-security/api/scan-async-request/

<!-- source: examples/asyncio/batch_async_scan.py -->

```python

import asyncio
import os
from pprint import pprint

import aisecurity
from aisecurity.generated_openapi_client import AiProfile
from aisecurity.generated_openapi_client import AsyncScanObject
from aisecurity.generated_openapi_client import ScanRequest
from aisecurity.generated_openapi_client import ScanRequestContentsInner

# IMPORTANT: For asyncio, import Scanner from aisecurity.scan.asyncio.scanner
from aisecurity.scan.asyncio.scanner import Scanner

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


async def main():
    response = await scanner.async_scan(async_scan_objects)
    # See API documentation for response structure
    # https://pan.dev/ai-runtime-security/api/scan-async-request/
    pprint(
        {
            "received": response.received,
            "scan_id": response.scan_id,
            "report_id": response.report_id,
        }
    )


if __name__ == "__main__":
    asyncio.run(main())
```

<a id="scan-results-example-asyncio" href="#scan-results-example-asyncio">

## Scan Results Example (asyncio)

</a>

API Reference: https://pan.dev/ai-runtime-security/api/get-scan-results-by-scan-i-ds/

<!-- source: examples/asyncio/scan_results.py -->

```python
import asyncio
from pprint import pprint

import aisecurity

# IMPORTANT: For asyncio, import Scanner from aisecurity.scan.asyncio.scanner
from aisecurity.scan.asyncio.scanner import Scanner

aisecurity.init()

scanner = Scanner()


async def main():
    # See API documentation for response structure
    # https://pan.dev/ai-runtime-security/api/get-scan-results-by-scan-i-ds/
    example_scan_id = "020e7c31-0000-4e0d-a2a6-215a0d5c56d9"
    scan_results = await scanner.query_by_scan_ids(scan_ids=[example_scan_id])
    pprint(scan_results)


if __name__ == "__main__":
    asyncio.run(main())
```

<a id="scan-reports-example-asyncio" href="#scan-reports-example-asyncio">

## Scan Reports Example (asyncio)

</a>

API Reference: https://pan.dev/ai-runtime-security/api/get-threat-scan-reports/

<!-- source: examples/asyncio/scan_reports.py -->

```python
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
    example_report_id = "020e7c31-0000-4e0d-a2a6-215a0d5c56d9"
    threat_scan_reports = await scanner.query_by_report_ids(
        report_ids=[example_report_id]
    )
    pprint(threat_scan_reports)


if __name__ == "__main__":
    asyncio.run(main())
```


<a id="examples-model-context-protocol" href="#examples-model-context-protocol">

# Examples: Model Context Protocol

</a>

<a id="model-context-protocol-server-example" href="#model-context-protocol-server-example">

## Model Context Protocol Server Example

</a>

<!-- source examples/model_context_protocol/server.py -->

```python
#!/usr/bin/env -S uv run fastmcp run -t sse # noqa: CPY001
"""
Palo Alto Networks AI Runtime Security (AIRS) API - Model Context Protocol (MCP) Server Example

This is an example MCP Server demonstrating the use of the AI Runtime Security API Intercept as MCP Tools.

The server exposes the AIRS API functionality of as various MCP tools:
- Inline Prompt/Response Scanning
- Batch (Asynchronous) Scanning for collections of Prompts/Responses
- Retrieval of Scan Results and Scan Threat Reports
"""
# PEP 723 Inline Script Metadata
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pan-aisecurity",
#     "fastmcp",
#     "python-dotenv",
# ]#
# ///

import asyncio
import itertools
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import dotenv
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from typing_extensions import Any, TypedDict

import aisecurity
from aisecurity.constants.base import (
    MAX_NUMBER_OF_BATCH_SCAN_OBJECTS,
    MAX_NUMBER_OF_SCAN_IDS,
)
from aisecurity.generated_openapi_client import (
    AsyncScanObject,
    AsyncScanResponse,
    ScanIdResult,
    ScanRequest,
    ScanRequestContentsInner,
    ScanResponse,
    ThreatScanReportObject,
)
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.asyncio.scanner import Scanner
from aisecurity.scan.models.content import Content
from aisecurity.utils import safe_flatten

ai_profile: AiProfile
scanner = Scanner()


@asynccontextmanager
async def mcp_lifespan_manager(*args, **kwargs) -> AsyncIterator[Any]:
    """Starlette Lifespan Context Manager

    This is required to close the shared aiohttp connection pool on server shutdown.
    """
    yield
    await scanner.close()


# Create the MCP Server with the lifespan context manager
mcp = FastMCP("aisecurity-scan-server", lifespan=mcp_lifespan_manager)


class SimpleScanContent(TypedDict):
    """SimpleScanContent is a TypedDict representing a greatly simplified ScanRequestContentsInner object."""

    prompt: str | None
    response: str | None


def pan_init():
    """Initialize the AI Runtime Security SDK (e.g. with your API Key).

    NOTE: You probably DON'T want to run aisecurity.init() at the module top-level
    to ensure the MCP Server Runtime Environment has a chance to set up environment
    variables _before_ this function is run.
    """
    global ai_profile

    # Load Environment variables from .env if available
    dotenv.load_dotenv()
    # Make this function run only once
    if getattr(pan_init, "__completed__", False):
        return
    if ai_profile_name := os.getenv("PANW_AI_PROFILE_NAME"):
        ai_profile = AiProfile(profile_name=ai_profile_name)
    elif ai_profile_id := os.getenv("PANW_AI_PROFILE_ID"):
        ai_profile = AiProfile(profile_id=ai_profile_id)
    else:
        raise ToolError("Missing AI Profile Name (PANW_AI_PROFILE_NAME) or AI Profile ID (PANW_AI_PROFILE_ID)")
    aisecurity.init(
        api_key=os.getenv("PANW_AI_SEC_API_KEY"),  # Optional - shows default fallback behavior
        api_endpoint=os.getenv("PANW_AI_SEC_API_ENDPOINT"),  # Optional - shows default fallback behavior
    )
    setattr(pan_init, "__completed__", True)


@mcp.tool()
async def pan_inline_scan(prompt: str | None = None, response: str | None = None) -> ScanResponse:
    """Submit a single Prompt and/or Model-Response (Scan Content) to be scanned synchronously.

    This is a blocking operation - the function will not return until the scan is complete
    or a timeout, (e.g. as configured in the AI Profile), is breached.

    Returns a complete Scan Response, notably the category (benign/malicious) and action (allow/block).

    See also: https://pan.dev/ai-runtime-security/api/scan-sync-request/
    """
    pan_init()
    if not prompt and not response:
        raise ToolError(f"Must provide at least one of prompt ({prompt}) and/or response ({response}).")
    scan_response = await scanner.sync_scan(
        ai_profile=ai_profile,
        content=Content(
            prompt=prompt,
            response=response,
        ),
    )
    return scan_response


@mcp.tool()
async def pan_batch_scan(
    scan_contents: list[SimpleScanContent],
) -> list[AsyncScanResponse]:
    """Submit multiple Scan Contents containing prompts/model-responses for asynchronous (batch) scanning.

    Automatically splits requests into batches of 5, which are submitted concurrently.

    Returns a list of AsyncScanResponse objects, each includes a scan_id and report_id,
    which can be used to retrieve scan results after the asynchronous scans are complete.

    See also: https://pan.dev/ai-runtime-security/api/scan-async-request/
    """
    global ai_profile

    pan_init()
    # build the AsyncScanContent object
    async_scan_batches: list[list[AsyncScanObject]] = []

    req_id = 0
    # Split into batches
    for batch in itertools.batched(scan_contents, MAX_NUMBER_OF_BATCH_SCAN_OBJECTS):
        async_scan_batches.append([
            AsyncScanObject(
                req_id=(req_id := req_id + 1),
                scan_req=ScanRequest(
                    ai_profile=ai_profile,
                    contents=[
                        ScanRequestContentsInner(
                            prompt=sc.get("prompt"),
                            response=sc.get("response"),
                        )
                    ],
                ),
            )
            for sc in batch
        ])

    # Process each batch concurrently via asyncio
    scan_coros = [scanner.async_scan(batch) for batch in async_scan_batches]
    bulk_scan_results: list[AsyncScanResponse] = await asyncio.gather(*scan_coros)

    return bulk_scan_results


@mcp.tool()
async def pan_get_scan_results(scan_ids: list[str]) -> list[ScanIdResult]:
    """Retrieve Scan Results with a list of Scan IDs.

    A Scan ID is a UUID string.

    See also: https://pan.dev/ai-runtime-security/api/get-scan-results-by-scan-i-ds/
    """
    pan_init()
    request_batches: list[list[str]] = []
    for batch in itertools.batched(scan_ids, MAX_NUMBER_OF_SCAN_IDS):
        request_batches.append(list(batch))

    # Process each batch concurrently via asyncio
    tasks = [scanner.query_by_scan_ids(batch) for batch in request_batches]
    batch_results: list[list[ScanIdResult]] = await asyncio.gather(*tasks, return_exceptions=True)

    # flatten nested list
    return safe_flatten(batch_results)


@mcp.tool()
async def pan_get_scan_reports(report_ids: list[str]) -> list[ThreatScanReportObject]:
    """Retrieve Scan Reports with a list of Scan Report IDs.

    A Scan Report ID is a Scan ID (UUID) prefixed with "R".

    See also: https://pan.dev/ai-runtime-security/api/get-scan-results-by-scan-i-ds/
    """
    pan_init()

    request_batches: list[list[str]] = []
    for batch in itertools.batched(report_ids, MAX_NUMBER_OF_SCAN_IDS):
        request_batches.append(list(batch))

    # Process each batch concurrently via asyncio
    tasks = [scanner.query_by_scan_ids(batch) for batch in request_batches]
    await asyncio.gather(*tasks, return_exceptions=True)

    threat_scan_reports = await scanner.query_by_report_ids(report_ids=report_ids)
    return threat_scan_reports


def maybe_monkeypatch_itertools_batched():
    # monkeypatch itertools on python < 3.12
    # This is required for python versions before 3.12, since itertools.batched was
    # added in python 3.12, and is required for the above functions to work.
    if sys.version_info.minor < 12:

        def batched(iterable, n, *, strict=False):
            if n < 1:
                raise ValueError("n must be at least one")
            iterator = iter(iterable)
            while batch := tuple(itertools.islice(iterator, n)):
                if strict and len(batch) != n:
                    raise ValueError("batched(): incomplete batch")
                yield batch

        setattr(itertools, "batched", batched)


if __name__ == "__main__":
    pan_init()
    maybe_monkeypatch_itertools_batched()
    asyncio.run(mcp.run_async())
```

<a id="error-handling--exceptions" href="#error-handling--exceptions">

# Error Handling & Exceptions

</a>

When the client is unable to fetch the expected response from the API server, a
subclass of `aisecurity.exceptions.AISecSDKException` is raised.

There are five types of Exceptions defined in `aisecurity/exceptions.py`:

- **AISEC_SERVER_SIDE_ERROR**: Errors returned by the API server. For example, an invalid API key.
- **AISEC_CLIENT_SIDE_ERROR**: Errors that occur on the client side. For example, a network connection issue.
- **AISEC_USER_REQUEST_PAYLOAD_ERROR**: Errors related to the user's request payload. For example, an empty scan object.
- **AISEC_MISSING_VARIABLE**: Errors related to missing variables. For example, missing API key environment variable.
- **AISEC_SDK_ERROR**: Other uncategorized errors that occur in the SDK.

<a id="compatibility-policy" href="#compatibility-policy">

# Compatability Policy

</a>

This package generally follows [SemVer v2](https://semver.org/spec/v2.0.0.html)
conventions, though certain backwards-incompatible changes may be released as
minor versions:

1. Changes that only affect static types, without breaking runtime behavior.
2. Changes to library internals which are technically public but not intended or
   documented for external use.
3. Changes that we do not expect to impact the vast majority of users in practice.

We take backwards-compatibility seriously and work hard to ensure you can rely
on a smooth upgrade experience. The major version number will be consistent with
API major version.

<a id="legal" href="#legal">

# Legal

</a>

Copyright (c) 2025, Palo Alto Networks

Licensed under the [Polyform Internal Use License 1.0.0](https://polyformproject.org/licenses/internal-use/1.0.0)
(the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at:

https://polyformproject.org/licenses/internal-use/1.0.0

(or)

https://github.com/polyformproject/polyform-licenses/blob/76a278c4/PolyForm-Internal-Use-1.0.0.md

As far as the law allows, the software comes as is, without any warranty
or condition, and the licensor will not be liable to you for any damages
arising out of these terms or the use or nature of the software, under
any kind of legal claim.

<!---Protected_by_PANW_Code_Armor_2024 - Y3ByfC9haWZ3L3B5dGhvbi1haXNlY3wxODI3MXxtYWlu --->
