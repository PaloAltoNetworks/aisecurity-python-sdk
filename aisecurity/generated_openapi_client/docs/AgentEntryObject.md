# AgentEntryObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**category_type** | **str** | Agent threat category type, such as \&quot;tools misuse\&quot;, \&quot;memory manipulation\&quot; and others | [optional] 
**verdict** | **str** | Verdict associated with the Agent threat Category, such as \&quot;malicious\&quot; or \&quot;benign\&quot; | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.agent_entry_object import AgentEntryObject

# TODO update the JSON string below
json = "{}"
# create an instance of AgentEntryObject from a JSON string
agent_entry_object_instance = AgentEntryObject.from_json(json)
# print the JSON string representation of the object
print(AgentEntryObject.to_json())

# convert the object into a dict
agent_entry_object_dict = agent_entry_object_instance.to_dict()
# create an instance of AgentEntryObject from a dict
agent_entry_object_from_dict = AgentEntryObject.from_dict(agent_entry_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


