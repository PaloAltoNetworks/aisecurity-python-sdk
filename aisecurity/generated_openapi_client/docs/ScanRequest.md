# ScanRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**tr_id** | **str** | Unique identifier for the transaction correlating prompt and response | [optional] 
**ai_profile** | [**AiProfile**](AiProfile.md) |  | 
**metadata** | [**Metadata**](Metadata.md) |  | [optional] 
**contents** | [**List[ScanRequestContentsInner]**](ScanRequestContentsInner.md) | List of prompt or response or prompt/response pairs. The last element is the one that needs to be scanned, and the previous elements are the context for the scan. | 

## Example

```python
from generated_openapi_client.models.scan_request import ScanRequest

# TODO update the JSON string below
json = "{}"
# create an instance of ScanRequest from a JSON string
scan_request_instance = ScanRequest.from_json(json)
# print the JSON string representation of the object
print(ScanRequest.to_json())

# convert the object into a dict
scan_request_dict = scan_request_instance.to_dict()
# create an instance of ScanRequest from a dict
scan_request_from_dict = ScanRequest.from_dict(scan_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


