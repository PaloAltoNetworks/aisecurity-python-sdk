# ToolDetectionDetails


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**topic_guardrails_details** | [**TopicGuardRails**](TopicGuardRails.md) |  | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.tool_detection_details import ToolDetectionDetails

# TODO update the JSON string below
json = "{}"
# create an instance of ToolDetectionDetails from a JSON string
tool_detection_details_instance = ToolDetectionDetails.from_json(json)
# print the JSON string representation of the object
print(ToolDetectionDetails.to_json())

# convert the object into a dict
tool_detection_details_dict = tool_detection_details_instance.to_dict()
# create an instance of ToolDetectionDetails from a dict
tool_detection_details_from_dict = ToolDetectionDetails.from_dict(tool_detection_details_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


