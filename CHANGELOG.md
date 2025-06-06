# Changelog

## 1.3.0 (2025-04-17)

1. **New Features**:
   1. Added Payload integrity check in open api generated API client file for Asyncio and inline SDK
      1. Payload includes new header parameter x-payload-hash.
      2. Updated utils file with generate_payload_hash method to generate payload hash.
      3. Added Unit tests for both open api generated API client file for Asyncio and inline SDK.
   2. Added User Agent parameter in header to define product name and its version.
   3. Add test scripts:
      1. load test


## 1.2.0 (2025-03-10)

1. **New Features**:
   1. Rename the two types of SDK usage:
      1. `aisecurity/scan/sync` to `aisecurity/scan/inline`
      2. `aisecurity/scan/async` to `aisecurity/scan/asyncio`
   2. Add test scripts:
      1. Functional test
      2. Performance test
      3. Integration test
   3. Update example code:
      1. Reconstruct examples of decorator to improve readability
      2. Rename examples file name to reflect SDK usage renaming
   4. Update Readme to improve readability

## 1.1.0 (2025-02-05)

1. **New Features**:
   1. Update aisecurity/configuration.py _Configuration.init():
      * Remove project = kwarg
      * Remove region = kwarg
      * Remove logging_level = kwarg
      * Remove logger = kwarg
      * Remove retry_strategy = kwarg
      * Add api_key = kwarg (Optional[str])
      * Add api_endpoint = kwarg (Optional[str])
      * Rename `attempts` to num_retries = kwarg (Optional[int])
      * Add `**kwargs` to support function signature backwards compatability.
        * Required since users are _already_ using the SDK, otherwise these would be breaking changes!
   2. Set the default api_endpoint to <https://service.api.aisecurity.paloaltonetworks.com>
   3. Updated the Logging strategy.User can build his own logger or use the default logger.
      * Not set logging Levels
   4. Updated the Retry strategy for Asyncio and Sync(Non Asyncio) both to  default exponential backoff
      * Removed Retry_Strategy file(aisecurity/retry_strategy.py)
   5. Removed the latency return variable from all APIs.
   6. Updated scan_executor.py to include tr_id and metadata parameters in sync_scan Api  for both Asyncio and Sync(Non Asyncio)

2. **Bug Fix**:
   1. Fixed the Content check in sync_scan Api (scan_executor.py) for both Asyncio and Sync(Non Asyncio)
   2. Fixed the type casting parameter for Retry for Sync(Non Asyncio)
   3. Fixed the scan ids check in query_by_scan_ids.py for both Asyncio and Sync(Non Asyncio)
   4. Fixed the report ids check in query_by_report_ids.py for both Asyncio and Sync(Non Asyncio)
   5. Fix unit test failures - tests/aisecurity/test_configuration.py
   6. Fix unit test failures - tests/aisecurity/scan/sync/*
   7. Fix unit test failures - tests/aisecurity/scan/asyncio/*

## 1.0.0 (2025-01-15)

1. **New Features**:
   1. Includes type definitions for all request params and response fields
   2. Offers both synchronous and asynchronous query to the scan service
   3. Easy configuration setup using environment variables
   4. Comprehensive error handling with custom exceptions
   5. Flexible retry strategies for both synchronous and asynchronous operations

## 0.3.0 (2024-12-18)

1. **New Features**:
   1. Added new exception handling,retry mechanism and utils
   2. Added code to invalidate checks
   3. Added Unit Tests for new exception handling,retry mechanism and utils

2. **Bug Fix**:
   1. Fix unit test failures - tests/aisecurity/scan/asyncio/*
   2. Fix unit test failures - tests/aisecurity/scan/sync/*
   3. Fix unit test failures - tests/aisecurity/test_configuration.py

## 0.2.0 (2024-12-11)

1. **New Features**:
   1. Support both Synchronous(Non Concurrent) and Asynchronous(Concurrent) request/response against aisec api
   2. Added unit tests for Asynchronous openapi client generated API's. - tests/aisecurity/generated_openapi_client/asyncio/*
   3. Add docker container build support for local development
2. **Bug Fix**:
   1. Fix unit test failures - tests/aisecurity/scan/asyncio/*
   2. Fix unit test failures - tests/aisecurity/scan/sync/*
   3. Fix unit test failures - tests/aisecurity/test_configuration.py

## 0.1.0 (2024-11-8)

Initial Release
