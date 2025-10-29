# ScanSummary


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**detections** | [**ToolDetectionFlags**](ToolDetectionFlags.md) |  | 
**threats** | **List[str]** |  | 

## Example

```python
from aisecurity.generated_openapi_client.models.scan_summary import ScanSummary

# TODO update the JSON string below
json = "{}"
# create an instance of ScanSummary from a JSON string
scan_summary_instance = ScanSummary.from_json(json)
# print the JSON string representation of the object
print(ScanSummary.to_json())

# convert the object into a dict
scan_summary_dict = scan_summary_instance.to_dict()
# create an instance of ScanSummary from a dict
scan_summary_from_dict = ScanSummary.from_dict(scan_summary_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


