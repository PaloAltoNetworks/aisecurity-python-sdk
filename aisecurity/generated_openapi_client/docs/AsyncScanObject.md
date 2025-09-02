# AsyncScanObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**req_id** | **int** | Unique identifier of an individual element sent in the batch scan request | 
**scan_req** | [**ScanRequest**](ScanRequest.md) |  | 

## Example

```python
from generated_openapi_client.models.async_scan_object import AsyncScanObject

# TODO update the JSON string below
json = "{}"
# create an instance of AsyncScanObject from a JSON string
async_scan_object_instance = AsyncScanObject.from_json(json)
# print the JSON string representation of the object
print(AsyncScanObject.to_json())

# convert the object into a dict
async_scan_object_dict = async_scan_object_instance.to_dict()
# create an instance of AsyncScanObject from a dict
async_scan_object_from_dict = AsyncScanObject.from_dict(async_scan_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


