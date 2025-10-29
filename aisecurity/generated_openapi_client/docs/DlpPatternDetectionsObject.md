# DlpPatternDetectionsObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**data_pattern_id** | **str** | Unique identifier for the data pattern matched | [optional] 
**version** | **int** | Version of the data pattern matched | [optional] 
**name** | **str** | Name of the data pattern matched | [optional] 
**high_confidence_detections** | **List[List[int]]** | Array of start, end offsets | [optional] 
**medium_confidence_detections** | **List[List[int]]** | Array of start, end offsets | [optional] 
**low_confidence_detections** | **List[List[int]]** | Array of start, end offsets | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.dlp_pattern_detections_object import DlpPatternDetectionsObject

# TODO update the JSON string below
json = "{}"
# create an instance of DlpPatternDetectionsObject from a JSON string
dlp_pattern_detections_object_instance = DlpPatternDetectionsObject.from_json(json)
# print the JSON string representation of the object
print(DlpPatternDetectionsObject.to_json())

# convert the object into a dict
dlp_pattern_detections_object_dict = dlp_pattern_detections_object_instance.to_dict()
# create an instance of DlpPatternDetectionsObject from a dict
dlp_pattern_detections_object_from_dict = DlpPatternDetectionsObject.from_dict(dlp_pattern_detections_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


