# ToolDetected


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**verdict** | **str** |  | [optional] 
**metadata** | [**ToolEventMetadata**](ToolEventMetadata.md) |  | [optional] 
**summary** | [**ScanSummary**](ScanSummary.md) |  | [optional] 
**input_detected** | [**IODetected**](IODetected.md) |  | [optional] 
**output_detected** | [**IODetected**](IODetected.md) |  | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.tool_detected import ToolDetected

# TODO update the JSON string below
json = "{}"
# create an instance of ToolDetected from a JSON string
tool_detected_instance = ToolDetected.from_json(json)
# print the JSON string representation of the object
print(ToolDetected.to_json())

# convert the object into a dict
tool_detected_dict = tool_detected_instance.to_dict()
# create an instance of ToolDetected from a dict
tool_detected_from_dict = ToolDetected.from_dict(tool_detected_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


