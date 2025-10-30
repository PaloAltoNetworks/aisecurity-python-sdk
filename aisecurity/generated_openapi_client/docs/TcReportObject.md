# TcReportObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**confidence** | **str** | Confidence level of the threat classification (“high\&quot; and \&quot;moderate\&quot;) | [optional] 
**verdict** | **str** | Detection service verdict such as \&quot;malicious\&quot; or \&quot;benign\&quot; | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.tc_report_object import TcReportObject

# TODO update the JSON string below
json = "{}"
# create an instance of TcReportObject from a JSON string
tc_report_object_instance = TcReportObject.from_json(json)
# print the JSON string representation of the object
print(TcReportObject.to_json())

# convert the object into a dict
tc_report_object_dict = tc_report_object_instance.to_dict()
# create an instance of TcReportObject from a dict
tc_report_object_from_dict = TcReportObject.from_dict(tc_report_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


