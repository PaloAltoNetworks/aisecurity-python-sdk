# UrlfEntryObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**url** | **str** | URL in the scan request | [optional] 
**risk_level** | **str** | Risk level associated with the URL, such as \&quot;high\&quot;, \&quot;medium\&quot;, or \&quot;low\&quot; | [optional] 
**categories** | **List[str]** | Categories associated with the URL | [optional] 

## Example

```python
from generated_openapi_client.models.urlf_entry_object import UrlfEntryObject

# TODO update the JSON string below
json = "{}"
# create an instance of UrlfEntryObject from a JSON string
urlf_entry_object_instance = UrlfEntryObject.from_json(json)
# print the JSON string representation of the object
print(UrlfEntryObject.to_json())

# convert the object into a dict
urlf_entry_object_dict = urlf_entry_object_instance.to_dict()
# create an instance of UrlfEntryObject from a dict
urlf_entry_object_from_dict = UrlfEntryObject.from_dict(urlf_entry_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


