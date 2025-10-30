# Generated OpenAPI Client - Changes

This document provides instructions for generating and maintaining the OpenAPI client code,
as well as tracking manual changes made to the generated code.

## Manual Changes

This section tracks manual modifications made to the generated OpenAPI client code that need to be
reapplied after regenerating the client. These changes are not preserved during code regeneration
and must be manually added back.

**Important:** After regenerating the client, review this list and reapply these changes.

## Changes List

### 1. PAYLOAD_HASH Header Addition

**Purpose:** Added custom header support for payload hash verification in API requests.

**Files Modified:**
- `aisecurity/generated_openapi_client/asyncio/api_client.py`
- `aisecurity/generated_openapi_client/urllib3/api_client.py`

**Description:** Implemented `PAYLOAD_HASH` header handling in both async and sync API clients
to support payload integrity verification for API requests.

### 2. Validation Functions for Scan Request

**Purpose:** Added custom validation functions for scan request IDs to enforce business rules.

**Files Modified:**
- `aisecurity/generated_openapi_client/models/scan_request.py`

**Description:** Implemented two validation functions:
- `validate_id_priority`: Validates ID priority constraints
- `validate_id_length`: Validates ID length requirements

These validators ensure that scan request IDs meet the required specifications before
being sent to the API.

