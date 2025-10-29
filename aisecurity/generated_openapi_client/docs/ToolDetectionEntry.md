# ToolDetectionEntry


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**tool_invoked** | **str** |  | [optional] 
**detections** | [**ToolDetectionFlags**](ToolDetectionFlags.md) |  | [optional] 
**threats** | **List[str]** |  | [optional] 
**details** | [**ToolDetectionDetails**](ToolDetectionDetails.md) |  | [optional] 
**masked_data** | [**MaskedData**](MaskedData.md) |  | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.tool_detection_entry import ToolDetectionEntry

# TODO update the JSON string below
json = "{}"
# create an instance of ToolDetectionEntry from a JSON string
tool_detection_entry_instance = ToolDetectionEntry.from_json(json)
# print the JSON string representation of the object
print(ToolDetectionEntry.to_json())

# convert the object into a dict
tool_detection_entry_dict = tool_detection_entry_instance.to_dict()
# create an instance of ToolDetectionEntry from a dict
tool_detection_entry_from_dict = ToolDetectionEntry.from_dict(tool_detection_entry_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


