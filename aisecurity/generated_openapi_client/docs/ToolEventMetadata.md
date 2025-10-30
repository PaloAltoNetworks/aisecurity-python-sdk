# ToolEventMetadata


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ecosystem** | **str** |  | 
**method** | **str** |  | 
**server_name** | **str** |  | 
**tool_invoked** | **str** |  | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.tool_event_metadata import ToolEventMetadata

# TODO update the JSON string below
json = "{}"
# create an instance of ToolEventMetadata from a JSON string
tool_event_metadata_instance = ToolEventMetadata.from_json(json)
# print the JSON string representation of the object
print(ToolEventMetadata.to_json())

# convert the object into a dict
tool_event_metadata_dict = tool_event_metadata_instance.to_dict()
# create an instance of ToolEventMetadata from a dict
tool_event_metadata_from_dict = ToolEventMetadata.from_dict(tool_event_metadata_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


