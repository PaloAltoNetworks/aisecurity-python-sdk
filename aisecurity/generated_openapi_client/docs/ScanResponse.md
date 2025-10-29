# ScanResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**source** | **str** | Source of the scan request (e.g., &#39;AI-Runtime-MCP-Server&#39; or &#39;AI-Runtime-API&#39;) | [optional] 
**report_id** | **str** | Unique identifier for the scan report | 
**scan_id** | **str** | Unique identifier for the scan | 
**tr_id** | **str** | Unique identifier for the transaction | [optional] 
**session_id** | **str** | Unique identifier for tracking Sessions | [optional] 
**profile_id** | **str** | Unique identifier of the AI security profile used for scanning | [optional] 
**profile_name** | **str** | AI security profile name used for scanning | [optional] 
**category** | **str** | Category of the scanned content verdicts such as \&quot;malicious\&quot; or \&quot;benign\&quot; | 
**action** | **str** | The action is set to \&quot;block\&quot; or \&quot;allow\&quot; based on AI security profile used for scanning | 
**prompt_detected** | [**PromptDetected**](PromptDetected.md) |  | [optional] 
**response_detected** | [**ResponseDetected**](ResponseDetected.md) |  | [optional] 
**prompt_masked_data** | [**MaskedData**](MaskedData.md) |  | [optional] 
**response_masked_data** | [**MaskedData**](MaskedData.md) |  | [optional] 
**prompt_detection_details** | [**PromptDetectionDetails**](PromptDetectionDetails.md) |  | [optional] 
**response_detection_details** | [**ResponseDetectionDetails**](ResponseDetectionDetails.md) |  | [optional] 
**tool_detected** | [**ToolDetected**](ToolDetected.md) |  | [optional] 
**created_at** | **datetime** | Scan request timestamp | [optional] 
**completed_at** | **datetime** | Scan completion timestamp | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.scan_response import ScanResponse

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


