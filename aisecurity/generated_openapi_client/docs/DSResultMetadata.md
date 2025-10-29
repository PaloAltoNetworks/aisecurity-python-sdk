# DSResultMetadata


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ecosystem** | **str** |  | [optional] 
**method** | **str** |  | [optional] 
**server_name** | **str** |  | [optional] 
**tool_invoked** | **str** |  | [optional] 
**direction** | **str** | Indicates the direction of data flow, either input to or output from a tool or service | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.ds_result_metadata import DSResultMetadata

# TODO update the JSON string below
json = "{}"
# create an instance of DSResultMetadata from a JSON string
ds_result_metadata_instance = DSResultMetadata.from_json(json)
# print the JSON string representation of the object
print(DSResultMetadata.to_json())

# convert the object into a dict
ds_result_metadata_dict = ds_result_metadata_instance.to_dict()
# create an instance of DSResultMetadata from a dict
ds_result_metadata_from_dict = DSResultMetadata.from_dict(ds_result_metadata_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


