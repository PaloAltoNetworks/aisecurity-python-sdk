# DbsEntryObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sub_type** | **str** | Database security sql query sub-type, such as \&quot;create\&quot;, \&quot;read\&quot;, \&quot;update\&quot;, or \&quot;delete\&quot; | [optional] 
**verdict** | **str** | Detection service verdict such as \&quot;malicious\&quot; or \&quot;benign\&quot; | [optional] 
**action** | **str** | The action is set to \&quot;block\&quot; or \&quot;allow\&quot; based on AI security profile used for scanning | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.dbs_entry_object import DbsEntryObject

# TODO update the JSON string below
json = "{}"
# create an instance of DbsEntryObject from a JSON string
dbs_entry_object_instance = DbsEntryObject.from_json(json)
# print the JSON string representation of the object
print(DbsEntryObject.to_json())

# convert the object into a dict
dbs_entry_object_dict = dbs_entry_object_instance.to_dict()
# create an instance of DbsEntryObject from a dict
dbs_entry_object_from_dict = DbsEntryObject.from_dict(dbs_entry_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


