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

from aisecurity.generated_openapi_client.models.urlf_entry_object import UrlfEntryObject


class TestUrlfEntryObject(unittest.TestCase):
    """UrlfEntryObject unit tests stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> UrlfEntryObject:
        """Test UrlfEntryObject
        include_optional is a boolean, when False only required
        params are included, when True both required and
        optional params are included
        """
        # uncomment below to create an instance of `UrlfEntryObject`
        """
        model = UrlfEntryObject()
        if include_optional:
            return UrlfEntryObject(
                url = '',
                risk_level = '',
                categories = [
                    ''
                    ]
            )
        else:
            return UrlfEntryObject(
        )
        """

        if include_optional:
            return UrlfEntryObject(
                url="http://malicious-example.com",
                risk_level="high",
                categories=["malware", "phishing"],
            )
        else:
            return UrlfEntryObject()

    def testUrlfEntryObject(self):
        """Test UrlfEntryObject"""
        inst_req_only = self.make_instance(include_optional=False)
        inst_req_and_optional = self.make_instance(include_optional=True)
        self.assertIsInstance(inst_req_only, UrlfEntryObject)
        self.assertIsNone(inst_req_only.url)
        self.assertIsNone(inst_req_only.risk_level)
        self.assertIsNone(inst_req_only.categories)

        # Assertions for instance with optional fields
        self.assertIsInstance(inst_req_and_optional, UrlfEntryObject)
        self.assertEqual(inst_req_and_optional.url, "http://malicious-example.com")
        self.assertEqual(inst_req_and_optional.risk_level, "high")
        self.assertListEqual(inst_req_and_optional.categories, ["malware", "phishing"])

        # Additional assertions
        self.assertNotEqual(inst_req_only, inst_req_and_optional)
        self.assertEqual(inst_req_only, UrlfEntryObject())
        self.assertEqual(
            inst_req_and_optional,
            UrlfEntryObject(
                url="http://malicious-example.com",
                risk_level="high",
                categories=["malware", "phishing"],
            ),
        )

        # Test individual attribute setting
        custom_entry = UrlfEntryObject(url="http://custom.com", risk_level="medium")
        self.assertEqual(custom_entry.url, "http://custom.com")
        self.assertEqual(custom_entry.risk_level, "medium")
        self.assertIsNone(custom_entry.categories)


if __name__ == "__main__":
    unittest.main()
