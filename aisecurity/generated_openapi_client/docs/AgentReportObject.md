# AgentReportObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**model_verdict** | **str** | Detection service verdict such as \&quot;malicious\&quot; or \&quot;benign\&quot; | [optional] 
**agent_framework** | **str** | Agent builder framework used to build Agents such as \&quot;AWS_Agent_Builder\&quot;, \&quot;Microsoft_copilot_studio\&quot; and others | [optional] 
**agent_patterns** | [**List[AgentEntryObject]**](AgentEntryObject.md) |  | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.agent_report_object import AgentReportObject

# TODO update the JSON string below
json = "{}"
# create an instance of AgentReportObject from a JSON string
agent_report_object_instance = AgentReportObject.from_json(json)
# print the JSON string representation of the object
print(AgentReportObject.to_json())

# convert the object into a dict
agent_report_object_dict = agent_report_object_instance.to_dict()
# create an instance of AgentReportObject from a dict
agent_report_object_from_dict = AgentReportObject.from_dict(agent_report_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


