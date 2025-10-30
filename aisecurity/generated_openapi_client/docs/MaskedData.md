# MaskedData


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**data** | **str** | Original data with sensitive pattern masked | [optional] 
**pattern_detections** | [**List[PatternDetections]**](PatternDetections.md) |  | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.masked_data import MaskedData

# TODO update the JSON string below
json = "{}"
# create an instance of MaskedData from a JSON string
masked_data_instance = MaskedData.from_json(json)
# print the JSON string representation of the object
print(MaskedData.to_json())

# convert the object into a dict
masked_data_dict = masked_data_instance.to_dict()
# create an instance of MaskedData from a dict
masked_data_from_dict = MaskedData.from_dict(masked_data_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


