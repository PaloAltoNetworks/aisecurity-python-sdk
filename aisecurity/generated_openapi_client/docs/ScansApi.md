# generated_openapi_client.ScansApi

All URIs are relative to *http://localhost:39090*

Method | HTTP request | Description
------------- | ------------- | -------------
[**scan_async_request**](ScansApi.md#scan_async_request) | **POST** /v1/scan/async/request | Send an Asynchronous Scan Request
[**scan_sync_request**](ScansApi.md#scan_sync_request) | **POST** /v1/scan/sync/request | Send a Synchronous Scan Request


# **scan_async_request**
> AsyncScanResponse scan_async_request(async_scan_object)

Send an Asynchronous Scan Request

Post a scan request that returns asynchronous scan response

### Example


```python
import generated_openapi_client
from generated_openapi_client.models.async_scan_object import AsyncScanObject
from generated_openapi_client.models.async_scan_response import AsyncScanResponse
from generated_openapi_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost:39090
# See configuration.py for a list of all supported configuration parameters.
configuration = generated_openapi_client.Configuration(
    host = "http://localhost:39090"
)


# Enter a context with an instance of the API client
with generated_openapi_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = generated_openapi_client.ScansApi(api_client)
    async_scan_object = None # List[List[AsyncScanObject]] | A list of scan request objects

    try:
        # Send an Asynchronous Scan Request
        api_response = api_instance.scan_async_request(async_scan_object)
        print("The response of ScansApi->scan_async_request:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ScansApi->scan_async_request: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **async_scan_object** | [**List[List[AsyncScanObject]]**](List.md)| A list of scan request objects | 

### Return type

[**AsyncScanResponse**](AsyncScanResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | successfully scanned request |  -  |
**0** | error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **scan_sync_request**
> ScanResponse scan_sync_request(scan_request)

Send a Synchronous Scan Request

Post a scan request containing prompt/model-response that returns a synchronous scan response

### Example


```python
import generated_openapi_client
from generated_openapi_client.models.scan_request import ScanRequest
from generated_openapi_client.models.scan_response import ScanResponse
from generated_openapi_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost:39090
# See configuration.py for a list of all supported configuration parameters.
configuration = generated_openapi_client.Configuration(
    host = "http://localhost:39090"
)


# Enter a context with an instance of the API client
with generated_openapi_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = generated_openapi_client.ScansApi(api_client)
    scan_request = generated_openapi_client.ScanRequest() # ScanRequest | Scan request object

    try:
        # Send a Synchronous Scan Request
        api_response = api_instance.scan_sync_request(scan_request)
        print("The response of ScansApi->scan_sync_request:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ScansApi->scan_sync_request: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **scan_request** | [**ScanRequest**](ScanRequest.md)| Scan request object | 

### Return type

[**ScanResponse**](ScanResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | successfully scanned request |  -  |
**0** | error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

