# CgReportObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**status** | **str** | Indicates the status of cg explanation such as  \&quot;completed\&quot; or \&quot;pending\&quot; | [optional] 
**explanation** | **str** | Indicates the the contextual grounding explanation given by the model | [optional] 
**category** | **str** | Indicates the predefined category of contextual grounding results | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.cg_report_object import CgReportObject

# TODO update the JSON string below
json = "{}"
# create an instance of CgReportObject from a JSON string
cg_report_object_instance = CgReportObject.from_json(json)
# print the JSON string representation of the object
print(CgReportObject.to_json())

# convert the object into a dict
cg_report_object_dict = cg_report_object_instance.to_dict()
# create an instance of CgReportObject from a dict
cg_report_object_from_dict = CgReportObject.from_dict(cg_report_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


