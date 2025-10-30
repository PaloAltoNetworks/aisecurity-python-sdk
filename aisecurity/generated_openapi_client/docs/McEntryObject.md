# McEntryObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**file_type** | **str** | code file type, such as \&quot;javascript\&quot;, \&quot;Python\&quot;, \&quot;VBScript\&quot; and others | [optional] 
**code_sha256** | **str** | SHA256 of the code file that was analyzed, such as a code snippet containing the potentially malicious code | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.mc_entry_object import McEntryObject

# TODO update the JSON string below
json = "{}"
# create an instance of McEntryObject from a JSON string
mc_entry_object_instance = McEntryObject.from_json(json)
# print the JSON string representation of the object
print(McEntryObject.to_json())

# convert the object into a dict
mc_entry_object_dict = mc_entry_object_instance.to_dict()
# create an instance of McEntryObject from a dict
mc_entry_object_from_dict = McEntryObject.from_dict(mc_entry_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


