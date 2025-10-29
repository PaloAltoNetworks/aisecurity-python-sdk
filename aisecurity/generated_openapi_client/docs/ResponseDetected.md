# ResponseDetected


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**url_cats** | **bool** | Indicates whether response contains any malicious URLs | [optional] 
**dlp** | **bool** | Indicates whether response contains any sensitive information | [optional] 
**db_security** | **bool** | Indicates whether response contains any database security threats | [optional] 
**toxic_content** | **bool** | Indicates whether response contains any harmful content | [optional] 
**malicious_code** | **bool** | Indicates whether response contains any malicious code | [optional] 
**agent** | **bool** | Indicates whether response contains any Agent related threats | [optional] 
**ungrounded** | **bool** | Indicates whether response contains any ungrounded content | [optional] 
**topic_violation** | **bool** | Indicates whether response contains any content violates topic guardrails | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.response_detected import ResponseDetected

# TODO update the JSON string below
json = "{}"
# create an instance of ResponseDetected from a JSON string
response_detected_instance = ResponseDetected.from_json(json)
# print the JSON string representation of the object
print(ResponseDetected.to_json())

# convert the object into a dict
response_detected_dict = response_detected_instance.to_dict()
# create an instance of ResponseDetected from a dict
response_detected_from_dict = ResponseDetected.from_dict(response_detected_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


