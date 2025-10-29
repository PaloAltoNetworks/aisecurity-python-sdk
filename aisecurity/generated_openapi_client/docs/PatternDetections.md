# PatternDetections


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pattern** | **str** | Matched pattern | [optional] 
**locations** | **List[List[int]]** | Array of start, end offsets | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.pattern_detections import PatternDetections

# TODO update the JSON string below
json = "{}"
# create an instance of PatternDetections from a JSON string
pattern_detections_instance = PatternDetections.from_json(json)
# print the JSON string representation of the object
print(PatternDetections.to_json())

# convert the object into a dict
pattern_detections_dict = pattern_detections_instance.to_dict()
# create an instance of PatternDetections from a dict
pattern_detections_from_dict = PatternDetections.from_dict(pattern_detections_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


