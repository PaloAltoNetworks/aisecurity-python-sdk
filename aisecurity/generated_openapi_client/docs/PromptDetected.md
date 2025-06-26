# PromptDetected


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**url_cats** | **bool** | Indicates whether prompt contains any malicious URLs | [optional] 
**dlp** | **bool** | Indicates whether prompt contains any sensitive information | [optional] 
**injection** | **bool** | Indicates whether prompt contains any injection threats | [optional] 

## Example

```python
from generated_openapi_client.models.prompt_detected import PromptDetected

# TODO update the JSON string below
json = "{}"
# create an instance of PromptDetected from a JSON string
prompt_detected_instance = PromptDetected.from_json(json)
# print the JSON string representation of the object
print(PromptDetected.to_json())

# convert the object into a dict
prompt_detected_dict = prompt_detected_instance.to_dict()
# create an instance of PromptDetected from a dict
prompt_detected_from_dict = PromptDetected.from_dict(prompt_detected_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


