# ToolEvent


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**metadata** | [**ToolEventMetadata**](ToolEventMetadata.md) |  | [optional] 
**input** | **str** | Raw JSON string of input to the server | [optional] 
**output** | **str** | Raw JSON string of output from the server | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.tool_event import ToolEvent

# TODO update the JSON string below
json = "{}"
# create an instance of ToolEvent from a JSON string
tool_event_instance = ToolEvent.from_json(json)
# print the JSON string representation of the object
print(ToolEvent.to_json())

# convert the object into a dict
tool_event_dict = tool_event_instance.to_dict()
# create an instance of ToolEvent from a dict
tool_event_from_dict = ToolEvent.from_dict(tool_event_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


