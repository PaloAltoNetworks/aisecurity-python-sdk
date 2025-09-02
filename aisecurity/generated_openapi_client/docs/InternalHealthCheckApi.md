# generated_openapi_client.InternalHealthCheckApi

All URIs are relative to *http://localhost:39090*

Method | HTTP request | Description
------------- | ------------- | -------------
[**internal_health_check**](InternalHealthCheckApi.md#internal_health_check) | **GET** /v1/internal/health | Internal API for health check


# **internal_health_check**
> internal_health_check()

Internal API for health check

Used by gateway/LB to probe service aliveness

### Example


```python
import generated_openapi_client
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
    api_instance = generated_openapi_client.InternalHealthCheckApi(api_client)

    try:
        # Internal API for health check
        api_instance.internal_health_check()
    except Exception as e:
        print("Exception when calling InternalHealthCheckApi->internal_health_check: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | 200 is the only response code for a health service |  -  |
**0** | error occurred |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

