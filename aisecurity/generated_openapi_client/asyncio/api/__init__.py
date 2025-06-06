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

# flake8: noqa

# import apis into api package
from aisecurity.generated_openapi_client.asyncio.api.internal_health_check_api import (
    InternalHealthCheckApi,
)
from aisecurity.generated_openapi_client.asyncio.api.scan_reports_api import (
    ScanReportsApi,
)
from aisecurity.generated_openapi_client.asyncio.api.scan_results_api import (
    ScanResultsApi,
)
from aisecurity.generated_openapi_client.asyncio.api.scans_api import ScansApi
