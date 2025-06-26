# generated_openapi_client.ScanResultsApi

All URIs are relative to *http://localhost:39090*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_scan_results_by_scan_ids**](ScanResultsApi.md#get_scan_results_by_scan_ids) | **GET** /v1/scan/results | Retrieve Scan Results by ScanIDs


# **get_scan_results_by_scan_ids**
> List[ScanIdResult] get_scan_results_by_scan_ids(scan_ids)

Retrieve Scan Results by ScanIDs

Get the Scan results for upto a maximum of 5 Scan IDs

### Example


```python
import generated_openapi_client
from generated_openapi_client.models.scan_id_result import ScanIdResult
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
    api_instance = generated_openapi_client.ScanResultsApi(api_client)
    scan_ids = ['scan_ids_example'] # List[str] | Scan Ids for Results

    try:
        # Retrieve Scan Results by ScanIDs
        api_response = api_instance.get_scan_results_by_scan_ids(scan_ids)
        print("The response of ScanResultsApi->get_scan_results_by_scan_ids:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ScanResultsApi->get_scan_results_by_scan_ids: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **scan_ids** | [**List[str]**](str.md)| Scan Ids for Results | 

### Return type

[**List[ScanIdResult]**](ScanIdResult.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successfully returned records for Scan Results |  -  |
**0** | error occurred |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

