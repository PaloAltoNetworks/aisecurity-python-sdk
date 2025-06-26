# AsyncScanResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**received** | **datetime** | Asynchronous scan received timestamp | 
**scan_id** | **str** | Unique identifier for the asynchronous scan request | 
**report_id** | **str** | Unique identifier for the asynchronous scan report | [optional] 

## Example

```python
from generated_openapi_client.models.async_scan_response import AsyncScanResponse

# TODO update the JSON string below
json = "{}"
# create an instance of AsyncScanResponse from a JSON string
async_scan_response_instance = AsyncScanResponse.from_json(json)
# print the JSON string representation of the object
print(AsyncScanResponse.to_json())

# convert the object into a dict
async_scan_response_dict = async_scan_response_instance.to_dict()
# create an instance of AsyncScanResponse from a dict
async_scan_response_from_dict = AsyncScanResponse.from_dict(async_scan_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


