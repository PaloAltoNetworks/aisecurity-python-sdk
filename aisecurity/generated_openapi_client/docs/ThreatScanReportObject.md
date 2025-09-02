# ThreatScanReportObject


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**report_id** | **str** | Unique identifier for the scan report | [optional] 
**scan_id** | **str** | Unique identifier for the scan | [optional] 
**req_id** | **int** | Unique identifier of an individual element sent in the batch scan request | [optional] 
**transaction_id** | **str** | Unique identifier for the transaction | [optional] 
**detection_results** | [**List[DetectionServiceResultObject]**](DetectionServiceResultObject.md) |  | [optional] 

## Example

```python
from generated_openapi_client.models.threat_scan_report_object import ThreatScanReportObject

# TODO update the JSON string below
json = "{}"
# create an instance of ThreatScanReportObject from a JSON string
threat_scan_report_object_instance = ThreatScanReportObject.from_json(json)
# print the JSON string representation of the object
print(ThreatScanReportObject.to_json())

# convert the object into a dict
threat_scan_report_object_dict = threat_scan_report_object_instance.to_dict()
# create an instance of ThreatScanReportObject from a dict
threat_scan_report_object_from_dict = ThreatScanReportObject.from_dict(threat_scan_report_object_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


