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
AISec API service

OpenAPI Specification for the AI Runtime Security API service

The version of the OpenAPI document: 0.0.0
Generated by OpenAPI Generator (https://openapi-generator.tech)

Do not edit the class manually.
"""

import unittest

from aisecurity.generated_openapi_client.asyncio.api.internal_health_check_api import (
    InternalHealthCheckApi,
)


class TestInternalHealthCheckApi(unittest.TestCase):
    """InternalHealthCheckApi unit tests stubs"""

    async def asyncSetUp(self) -> None:
        self.api = InternalHealthCheckApi()

    async def asyncTearDown(self) -> None:
        pass

    async def test_internal_health_check(self) -> None:
        """Test case for internal_health_check

        Internal API for health check
        """
        pass


if __name__ == "__main__":
    unittest.main()
