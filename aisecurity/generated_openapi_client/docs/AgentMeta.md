# AgentMeta


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**agent_id** | **str** | Agent identifier | [optional] 
**agent_version** | **str** | Agent version | [optional] 
**agent_arn** | **str** | Agent ARN | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.agent_meta import AgentMeta

# TODO update the JSON string below
json = "{}"
# create an instance of AgentMeta from a JSON string
agent_meta_instance = AgentMeta.from_json(json)
# print the JSON string representation of the object
print(AgentMeta.to_json())

# convert the object into a dict
agent_meta_dict = agent_meta_instance.to_dict()
# create an instance of AgentMeta from a dict
agent_meta_from_dict = AgentMeta.from_dict(agent_meta_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


