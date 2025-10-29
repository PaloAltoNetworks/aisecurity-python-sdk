# ResponseDetectionDetails


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**topic_guardrails_details** | [**TopicGuardRails**](TopicGuardRails.md) |  | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.response_detection_details import ResponseDetectionDetails

# TODO update the JSON string below
json = "{}"
# create an instance of ResponseDetectionDetails from a JSON string
response_detection_details_instance = ResponseDetectionDetails.from_json(json)
# print the JSON string representation of the object
print(ResponseDetectionDetails.to_json())

# convert the object into a dict
response_detection_details_dict = response_detection_details_instance.to_dict()
# create an instance of ResponseDetectionDetails from a dict
response_detection_details_from_dict = ResponseDetectionDetails.from_dict(response_detection_details_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


