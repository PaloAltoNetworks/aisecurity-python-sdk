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

# Header key

import aisecurity._version

HEADER_API_KEY = "x-pan-token"
PAYLOAD_HASH = "x-payload-hash"
USER_AGENT = f"PAN-AIRS/{aisecurity._version.__version__}-python-sdk"

DEFAULT_ENDPOINT = "https://service.api.aisecurity.paloaltonetworks.com"

# Environment variables
AI_SEC_API_KEY = "PANW_AI_SEC_API_KEY"
AI_SEC_API_ENDPOINT = "PANW_AI_SEC_API_ENDPOINT"

# Content length limits
MAX_CONTENT_PROMPT_LENGTH = 2 * 1024 * 1024
MAX_CONTENT_RESPONSE_LENGTH = 2 * 1024 * 1024

# Key ID length constraint
MAX_API_KEY_LENGTH = 2048


# Request IDs constraints
MAX_TRANSACTION_ID_STR_LENGTH = 100
MAX_SCAN_ID_STR_LENGTH = 36
MAX_NUMBER_OF_SCAN_IDS = 5
MAX_REPORT_ID_STR_LENGTH = 40
MAX_NUMBER_OF_REPORT_IDS = 5
MAX_AI_PROFILE_NAME_LENGTH = 100
MAX_NUMBER_OF_BATCH_SCAN_OBJECTS = 5

# API Client
MAX_CONNECTION_POOL_SIZE = 100
MAX_NUMBER_OF_RETRIES = 5
HTTP_FORCE_RETRY_STATUS_CODES = [500, 502, 503, 504]
