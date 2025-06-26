# AiProfile


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**profile_id** | **str** | Unique identifier for the profile. If not provided, then profile_name is required. | [optional] 
**profile_name** | **str** | Name of the profile. If not provided, then profile_id is required. | [optional] 

## Example

```python
from generated_openapi_client.models.ai_profile import AiProfile

# TODO update the JSON string below
json = "{}"
# create an instance of AiProfile from a JSON string
ai_profile_instance = AiProfile.from_json(json)
# print the JSON string representation of the object
print(AiProfile.to_json())

# convert the object into a dict
ai_profile_dict = ai_profile_instance.to_dict()
# create an instance of AiProfile from a dict
ai_profile_from_dict = AiProfile.from_dict(ai_profile_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


