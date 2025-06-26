# ScanSyncRequestDefaultResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**message** | **str** |  | [optional] 
**error** | **str** |  | [optional] 

## Example

```python
from generated_openapi_client.models.scan_sync_request_default_response import ScanSyncRequestDefaultResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ScanSyncRequestDefaultResponse from a JSON string
scan_sync_request_default_response_instance = ScanSyncRequestDefaultResponse.from_json(json)
# print the JSON string representation of the object
print(ScanSyncRequestDefaultResponse.to_json())

# convert the object into a dict
scan_sync_request_default_response_dict = scan_sync_request_default_response_instance.to_dict()
# create an instance of ScanSyncRequestDefaultResponse from a dict
scan_sync_request_default_response_from_dict = ScanSyncRequestDefaultResponse.from_dict(scan_sync_request_default_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


