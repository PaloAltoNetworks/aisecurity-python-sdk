# ScanIdResult


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**req_id** | **int** | Unique identifier of an individual element sent in the batch scan request | [optional] 
**status** | **str** | Scan request processing state such as \&quot;complete\&quot; or \&quot;pending\&quot; | [optional] 
**scan_id** | **str** | Unique identifier for the scan | [optional] 
**result** | [**ScanResponse**](ScanResponse.md) |  | [optional] 

## Example

```python
from generated_openapi_client.models.scan_id_result import ScanIdResult

# TODO update the JSON string below
json = "{}"
# create an instance of ScanIdResult from a JSON string
scan_id_result_instance = ScanIdResult.from_json(json)
# print the JSON string representation of the object
print(ScanIdResult.to_json())

# convert the object into a dict
scan_id_result_dict = scan_id_result_instance.to_dict()
# create an instance of ScanIdResult from a dict
scan_id_result_from_dict = ScanIdResult.from_dict(scan_id_result_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


