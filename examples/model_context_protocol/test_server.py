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

from __future__ import annotations

import dataclasses
import json
import os
import sys
from pathlib import Path
from typing import Optional

import dotenv
import pytest
import pytest_asyncio

pytestmark = pytest.mark.asyncio(loop_scope="module")


if sys.version_info < (3, 10):  # UP036 is broken when interpreting this?
    pytest.skip(reason="requires python3.10 or higher", allow_module_level=True)
    Client = None
    ToolError = None
    TextContent = None
else:
    from fastmcp import Client
    from fastmcp.exceptions import ToolError
    from mcp.types import TextContent

if not os.getenv("PANW_AI_PROFILE_NAME") and not os.getenv("PANW_AI_PROFILE_ID"):
    pytest.skip("Missing PANW_AI_PROFILE_NAME/PANW_AI_PROFILE_ID environment variables", allow_module_level=True)
if not os.getenv("PANW_AI_SEC_API_KEY"):
    pytest.skip("Missing PANW_AI_SEC_API_KEY environment variable", allow_module_level=True)


def setup_module():
    __self__ = Path(__file__)
    sys.path.append(str(__self__.parent))

    dotenv.load_dotenv()
    import server

    server.maybe_monkeypatch_itertools_batched()


@dataclasses.dataclass
class PromptTestCase:
    prompt: Optional[str] = None
    response: Optional[str] = None
    exception: Optional[type(Exception)] = None

    def pr(self):
        """Get just the prompt and response as a dict (e.g. for SimpleScanContent)"""
        return {"prompt": self.prompt, "response": self.response}


@pytest_asyncio.fixture(scope="module")
def mcp_server():
    import server

    server.pan_init()
    return server.mcp


prompt_test_cases = [
    PromptTestCase("sdkmcp test prompt with response", "sdkmcp test response with prompt", None),
    PromptTestCase("sdkmcp test prompt without response", None, None),
    PromptTestCase(None, "sdkmcp test response without prompt", None),
    PromptTestCase(None, None, ToolError),
]


@pytest_asyncio.fixture(scope="module", params=prompt_test_cases)
def ptc(request):
    yield request.param


batch_prompt_test_cases = [
    [PromptTestCase(f"sdkmcp test prompt {i}", f"sdkmcp test response {i}") for i in range(1)],
    [PromptTestCase(f"sdkmcp test prompt {i}", f"sdkmcp test response {i}") for i in range(5)],
    [PromptTestCase(f"sdkmcp test prompt {i}", f"sdkmcp test response {i}") for i in range(6)],
    [PromptTestCase(f"sdkmcp test prompt {i}", f"sdkmcp test response {i}") for i in range(15)],
    [PromptTestCase(f"sdkmcp test prompt {i}", f"sdkmcp test response {i}") for i in range(16)],
    [PromptTestCase(f"sdkmcp test prompt {i}", None) for i in range(1)],
    [PromptTestCase(None, f"test Response {i}") for i in range(1)],
    [PromptTestCase(None, None, ToolError) for i in range(1)],
]


@pytest_asyncio.fixture(scope="module", params=batch_prompt_test_cases)
def bptc(request):
    yield request.param


@pytest.mark.asyncio(loop_scope="module")
async def test_mcp_pan_inline_scan(mcp_server, ptc):
    async with Client(mcp_server) as client:
        try:
            tool_output: list[TextContent] = await client.call_tool("pan_inline_scan", ptc.pr())
        except ToolError:
            if ptc.exception is not None:
                return
            raise
        assert isinstance(tool_output[0], TextContent)
        scan_result: dict = json.loads(tool_output[0].text)
        assert isinstance(scan_result.get("scan_id", None), str)
        assert isinstance(scan_result.get("report_id", None), str)


@pytest.mark.asyncio(loop_scope="module")
async def test_pan_inline_scan(mcp_server, ptc):
    async with Client(mcp_server) as client:
        try:
            tool_output: list[TextContent] = await client.call_tool("pan_inline_scan", ptc.pr())
        except ToolError:
            if ptc.exception is not None:
                return
            raise
        assert isinstance(tool_output[0], TextContent)
        scan_result: dict = json.loads(tool_output[0].text)
        assert isinstance(scan_result.get("scan_id", None), str)
        assert isinstance(scan_result.get("report_id", None), str)


@pytest.mark.asyncio(loop_scope="module")
async def test_mcp_pan_batch_scan(mcp_server, bptc):
    async with Client(mcp_server) as client:
        try:
            tool_output: list[TextContent] = await client.call_tool(
                "pan_batch_scan", {"scan_contents": [tc.pr() for tc in bptc]}
            )
        except ToolError:
            if any([tc.exception is not None for tc in bptc]):
                return
            raise
        assert isinstance(tool_output[0], TextContent)
        batch_scan_results: list[dict] = json.loads(tool_output[0].text)
        batch_count = len(bptc)
        scan_result_count = int(batch_count / 5)
        scan_result_count += 1 if batch_count % 5 > 0 else 0
        assert len(batch_scan_results) == scan_result_count
        assert isinstance(batch_scan_results[0].get("scan_id", None), str)
        assert isinstance(batch_scan_results[0].get("report_id", None), str)
