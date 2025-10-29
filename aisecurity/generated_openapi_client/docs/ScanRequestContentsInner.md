# ScanRequestContentsInner


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**prompt** | **str** | The prompt content that you want to scan | [optional] 
**response** | **str** | The response content that you want to scan | [optional] 
**code_prompt** | **str** | Code snippet extracted from Prompt content that you want to scan | [optional] 
**code_response** | **str** | Code snippet extracted from Response content that you want to scan | [optional] 
**context** | **str** | The data context for contextual grounding | [optional] 
**tool_event** | [**ToolEvent**](ToolEvent.md) |  | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.scan_request_contents_inner import ScanRequestContentsInner

# TODO update the JSON string below
json = "{}"
# create an instance of ScanRequestContentsInner from a JSON string
scan_request_contents_inner_instance = ScanRequestContentsInner.from_json(json)
# print the JSON string representation of the object
print(ScanRequestContentsInner.to_json())

# convert the object into a dict
scan_request_contents_inner_dict = scan_request_contents_inner_instance.to_dict()
# create an instance of ScanRequestContentsInner from a dict
scan_request_contents_inner_from_dict = ScanRequestContentsInner.from_dict(scan_request_contents_inner_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


