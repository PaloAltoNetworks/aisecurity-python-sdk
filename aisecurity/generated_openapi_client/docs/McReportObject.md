# McReportObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**verdict** | **str** | Detection service verdict such as \&quot;malicious\&quot; or \&quot;benign\&quot; | [optional] 
**code_analysis_by_type** | [**List[McEntryObject]**](McEntryObject.md) |  | [optional] 
**all_code_blocks** | **List[str]** |  | [optional] 

## Example

```python
from generated_openapi_client.models.mc_report_object import McReportObject

# TODO update the JSON string below
json = "{}"
# create an instance of McReportObject from a JSON string
mc_report_object_instance = McReportObject.from_json(json)
# print the JSON string representation of the object
print(McReportObject.to_json())

# convert the object into a dict
mc_report_object_dict = mc_report_object_instance.to_dict()
# create an instance of McReportObject from a dict
mc_report_object_from_dict = McReportObject.from_dict(mc_report_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


