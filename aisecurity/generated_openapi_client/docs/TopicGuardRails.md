# TopicGuardRails


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**allowed_topics** | **List[str]** | Indicates the list of allowed topics if there was a content match for the topic allow list | [optional] 
**blocked_topics** | **List[str]** | Indicates the list of blocked topics if there was a content match for the topic block list | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.topic_guard_rails import TopicGuardRails

# TODO update the JSON string below
json = "{}"
# create an instance of TopicGuardRails from a JSON string
topic_guard_rails_instance = TopicGuardRails.from_json(json)
# print the JSON string representation of the object
print(TopicGuardRails.to_json())

# convert the object into a dict
topic_guard_rails_dict = topic_guard_rails_instance.to_dict()
# create an instance of TopicGuardRails from a dict
topic_guard_rails_from_dict = TopicGuardRails.from_dict(topic_guard_rails_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


