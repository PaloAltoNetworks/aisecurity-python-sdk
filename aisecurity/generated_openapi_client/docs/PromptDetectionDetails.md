# PromptDetectionDetails


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**topic_guardrails_details** | [**TopicGuardRails**](TopicGuardRails.md) |  | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.prompt_detection_details import PromptDetectionDetails

# TODO update the JSON string below
json = "{}"
# create an instance of PromptDetectionDetails from a JSON string
prompt_detection_details_instance = PromptDetectionDetails.from_json(json)
# print the JSON string representation of the object
print(PromptDetectionDetails.to_json())

# convert the object into a dict
prompt_detection_details_dict = prompt_detection_details_instance.to_dict()
# create an instance of PromptDetectionDetails from a dict
prompt_detection_details_from_dict = PromptDetectionDetails.from_dict(prompt_detection_details_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


