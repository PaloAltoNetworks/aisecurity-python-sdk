# ToolDetectionFlags


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**injection** | **bool** | Indicates whether the content contains any injection threats | [optional] 
**url_cats** | **bool** | Indicates whether response contains any malicious URLs | [optional] 
**dlp** | **bool** | Indicates whether response contains any sensitive information | [optional] 
**db_security** | **bool** | Indicates whether response contains any database security threats | [optional] 
**toxic_content** | **bool** | Indicates whether response contains any harmful content | [optional] 
**malicious_code** | **bool** | Indicates whether response contains any malicious code | [optional] 
**agent** | **bool** | Indicates whether response contains any Agent related threats | [optional] 
**topic_violation** | **bool** | Indicates whether prompt contains any content violates topic guardrails | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.tool_detection_flags import ToolDetectionFlags

# TODO update the JSON string below
json = "{}"
# create an instance of ToolDetectionFlags from a JSON string
tool_detection_flags_instance = ToolDetectionFlags.from_json(json)
# print the JSON string representation of the object
print(ToolDetectionFlags.to_json())

# convert the object into a dict
tool_detection_flags_dict = tool_detection_flags_instance.to_dict()
# create an instance of ToolDetectionFlags from a dict
tool_detection_flags_from_dict = ToolDetectionFlags.from_dict(tool_detection_flags_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


