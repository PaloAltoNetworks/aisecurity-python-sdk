# DetectionServiceResultObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**data_type** | **str** | Content type such as \&quot;prompt\&quot; or \&quot;response\&quot; | [optional] 
**detection_service** | **str** | Detection service name generating the results such as \&quot;urlf\&quot;, \&quot;dlp\&quot;, and \&quot;prompt injection\&quot; | [optional] 
**verdict** | **str** | Detection service verdict such as \&quot;malicious\&quot; or \&quot;benign\&quot; | [optional] 
**action** | **str** | The action is set to \&quot;block\&quot; or \&quot;allow\&quot; based on AI security profile used for scanning | [optional] 
**result_detail** | [**DSDetailResultObject**](DSDetailResultObject.md) |  | [optional] 

## Example

```python
from generated_openapi_client.models.detection_service_result_object import DetectionServiceResultObject

# TODO update the JSON string below
json = "{}"
# create an instance of DetectionServiceResultObject from a JSON string
detection_service_result_object_instance = DetectionServiceResultObject.from_json(json)
# print the JSON string representation of the object
print(DetectionServiceResultObject.to_json())

# convert the object into a dict
detection_service_result_object_dict = detection_service_result_object_instance.to_dict()
# create an instance of DetectionServiceResultObject from a dict
detection_service_result_object_from_dict = DetectionServiceResultObject.from_dict(detection_service_result_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


