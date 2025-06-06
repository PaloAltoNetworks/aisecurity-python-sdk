# Copyright (c) 2025, Palo Alto Networks
#
# Licensed under the Polyform Internal Use License 1.0.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
#
# https://polyformproject.org/licenses/internal-use/1.0.0
# (or)
# https://github.com/polyformproject/polyform-licenses/blob/76a278c4/PolyForm-Internal-Use-1.0.0.md
#
# As far as the law allows, the software comes as is, without any warranty
# or condition, and the licensor will not be liable to you for any damages
# arising out of these terms or the use or nature of the software, under
# any kind of legal claim.

"""
AISec API service

OpenAPI Specification for the AI Runtime Security API service

The version of the OpenAPI document: 0.0.0
Generated by OpenAPI Generator (https://openapi-generator.tech)

Do not edit the class manually.
"""

import unittest

from aisecurity.generated_openapi_client.models.dlp_report_object import DlpReportObject


class TestDlpReportObject(unittest.TestCase):
    """DlpReportObject unit tests stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> DlpReportObject:
        """Test DlpReportObject
        include_optional is a boolean, when False only required
        params are included, when True both required and
        optional params are included
        """
        # uncomment below to create an instance of `DlpReportObject`
        if include_optional:
            return DlpReportObject(
                dlp_report_id="DLP-123456",
                dlp_profile_name="Sensitive Data Profile",
                dlp_profile_id="PROF-789",
                dlp_profile_version=2,
                data_pattern_rule1_verdict="NOT MATCHED",
                data_pattern_rule2_verdict="MATCHED",
            )
        else:
            return DlpReportObject()

    def testDlpReportObject(self):
        """Test DlpReportObject"""
        dlp_report_object = self.make_instance(include_optional=False)
        dlp_report_object_optional = self.make_instance(include_optional=True)

        # Assert for the case when include_optional is False
        self.assertIsInstance(dlp_report_object, DlpReportObject)
        self.assertIsNone(dlp_report_object.dlp_report_id)
        self.assertIsNone(dlp_report_object.dlp_profile_name)
        self.assertIsNone(dlp_report_object.dlp_profile_id)
        self.assertIsNone(dlp_report_object.dlp_profile_version)
        self.assertIsNone(dlp_report_object.data_pattern_rule1_verdict)
        self.assertIsNone(dlp_report_object.data_pattern_rule2_verdict)

        # Assert for the case when include_optional is True
        self.assertIsInstance(dlp_report_object_optional, DlpReportObject)
        self.assertEqual(dlp_report_object_optional.dlp_report_id, "DLP-123456")
        self.assertEqual(dlp_report_object_optional.dlp_profile_name, "Sensitive Data Profile")
        self.assertEqual(dlp_report_object_optional.dlp_profile_id, "PROF-789")
        self.assertEqual(dlp_report_object_optional.dlp_profile_version, 2)
        self.assertEqual(dlp_report_object_optional.data_pattern_rule1_verdict, "NOT MATCHED")
        self.assertEqual(dlp_report_object_optional.data_pattern_rule2_verdict, "MATCHED")


if __name__ == "__main__":
    unittest.main()
