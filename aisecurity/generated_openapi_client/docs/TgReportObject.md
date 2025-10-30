# TgReportObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**allowed_topic_list** | **str** | Indicates whether there was a content match for the topic allow list such as \&quot;MATCHED\&quot; or \&quot;NOT MATCHED\&quot; | [optional] 
**blocked_topic_list** | **str** | Indicates whether there was a content match for the topic block list such as \&quot;MATCHED\&quot; or \&quot;NOT MATCHED\&quot; | [optional] 
**allowed_topics** | **List[str]** | Indicates the list of allowed topics if there was a content match for the topic allow list | [optional] 
**blocked_topics** | **List[str]** | Indicates the list of blocked topics if there was a content match for the topic allow list | [optional] 

## Example

```python
from aisecurity.generated_openapi_client.models.tg_report_object import TgReportObject

# TODO update the JSON string below
json = "{}"
# create an instance of TgReportObject from a JSON string
tg_report_object_instance = TgReportObject.from_json(json)
# print the JSON string representation of the object
print(TgReportObject.to_json())

# convert the object into a dict
tg_report_object_dict = tg_report_object_instance.to_dict()
# create an instance of TgReportObject from a dict
tg_report_object_from_dict = TgReportObject.from_dict(tg_report_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


