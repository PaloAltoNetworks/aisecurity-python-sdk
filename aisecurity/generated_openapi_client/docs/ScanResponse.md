# ScanResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**report_id** | **str** | Unique identifier for the scan report | 
**scan_id** | **str** | Unique identifier for the scan | 
**tr_id** | **str** | Unique identifier for the transaction | [optional] 
**profile_id** | **str** | Unique identifier of the AI security profile used for scanning | [optional] 
**profile_name** | **str** | AI security profile name used for scanning | [optional] 
**category** | **str** | Category of the scanned content verdicts such as \&quot;malicious\&quot; or \&quot;benign\&quot; | 
**action** | **str** | The action is set to \&quot;block\&quot; or \&quot;allow\&quot; based on AI security profile used for scanning | 
**prompt_detected** | [**PromptDetected**](PromptDetected.md) |  | [optional] 
**response_detected** | [**ResponseDetected**](ResponseDetected.md) |  | [optional] 
**created_at** | **datetime** | Scan request timestamp | [optional] 
**completed_at** | **datetime** | Scan completion timestamp | [optional] 

## Example

```python
from generated_openapi_client.models.scan_response import ScanResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ScanResponse from a JSON string
scan_response_instance = ScanResponse.from_json(json)
# print the JSON string representation of the object
print(ScanResponse.to_json())

# convert the object into a dict
scan_response_dict = scan_response_instance.to_dict()
# create an instance of ScanResponse from a dict
scan_response_from_dict = ScanResponse.from_dict(scan_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


