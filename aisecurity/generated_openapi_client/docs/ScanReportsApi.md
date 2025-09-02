# generated_openapi_client.ScanReportsApi

All URIs are relative to *http://localhost:39090*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_threat_scan_reports**](ScanReportsApi.md#get_threat_scan_reports) | **GET** /v1/scan/reports | Retrieve Threat Scan Reports by Report IDs


# **get_threat_scan_reports**
> List[ThreatScanReportObject] get_threat_scan_reports(report_ids)

Retrieve Threat Scan Reports by Report IDs

Get the Threat Scan Reports for a given list of report_ids

### Example


```python
import generated_openapi_client
from generated_openapi_client.models.threat_scan_report_object import ThreatScanReportObject
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
    api_instance = generated_openapi_client.ScanReportsApi(api_client)
    report_ids = ['report_ids_example'] # List[str] | Report Ids for Results

    try:
        # Retrieve Threat Scan Reports by Report IDs
        api_response = api_instance.get_threat_scan_reports(report_ids)
        print("The response of ScanReportsApi->get_threat_scan_reports:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ScanReportsApi->get_threat_scan_reports: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **report_ids** | [**List[str]**](str.md)| Report Ids for Results | 

### Return type

[**List[ThreatScanReportObject]**](ThreatScanReportObject.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successfully returned Threat Scan Reports |  -  |
**0** | error occurred |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

