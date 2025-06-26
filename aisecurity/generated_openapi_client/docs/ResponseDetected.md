# ResponseDetected


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**url_cats** | **bool** | Indicates whether response contains any malicious URLs | [optional] 
**dlp** | **bool** | Indicates whether response contains any sensitive information | [optional] 

## Example

```python
from generated_openapi_client.models.response_detected import ResponseDetected

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


