# DlpReportObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**dlp_report_id** | **str** | Unique identifier for the DLP report | [optional] 
**dlp_profile_name** | **str** | DLP profile name used for the scan | [optional] 
**dlp_profile_id** | **str** | Unique identifier for the DLP profile used for the scan | [optional] 
**dlp_profile_version** | **int** | Version of the DLP profile used for the scan | [optional] 
**data_pattern_rule1_verdict** | **str** | Indicates whether there was a content match for this rule such as \&quot;MATCHED\&quot; or \&quot;NOT MATCHED\&quot; | [optional] 
**data_pattern_rule2_verdict** | **str** | Indicates whether there was a content match for this rule such as \&quot;MATCHED\&quot; or \&quot;NOT MATCHED\&quot; | [optional] 

## Example

```python
from generated_openapi_client.models.dlp_report_object import DlpReportObject

# TODO update the JSON string below
json = "{}"
# create an instance of DlpReportObject from a JSON string
dlp_report_object_instance = DlpReportObject.from_json(json)
# print the JSON string representation of the object
print(DlpReportObject.to_json())

# convert the object into a dict
dlp_report_object_dict = dlp_report_object_instance.to_dict()
# create an instance of DlpReportObject from a dict
dlp_report_object_from_dict = DlpReportObject.from_dict(dlp_report_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


