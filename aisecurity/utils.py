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

import hashlib
import hmac
import json
import uuid
from typing import Any, Union


class Utils:
    @staticmethod
    def is_valid_uuid(id_string: str) -> bool:
        """
        Check if a given string is a valid UUID.

        Args:
        id_string (str): The string to check.

        Returns:
        bool: True if the string is a valid UUID, False otherwise.
        """
        try:
            uuid_obj = uuid.UUID(id_string)
            return str(uuid_obj) == id_string.lower()
        except ValueError:
            return False

    @staticmethod
    def generate_payload_hash(api_key: str, body: Any) -> str:
        """
        Generate an HMAC-SHA256 hash of the request body using the API key as the secret.

        Args:
            api_key: The API key used as the secret key
            body: The request body to be hashed

        Returns:
            str: Hexadecimal digest of the HMAC hash
        """
        try:
            body_str = json.dumps(body)
            digest = hmac.new(
                key=api_key.encode("utf-8"),
                msg=body_str.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).hexdigest()
            return digest
        except (TypeError, ValueError, ImportError) as e:
            raise e


def safe_flatten(maybe_list_of_lists: list[Union[list[Any], Any]]) -> list[Any]:
    """
    Safely flattens a list that may contain nested lists.

    Args:
        maybe_list_of_lists (list[Union[list[Any], Any]]): A list that may contain nested lists.

    Returns:
        list[Any]: A flattened list containing all elements.

    Raises:
        ValueError: If the input is not a list.
    """
    new_list: list[Any] = []
    if not isinstance(maybe_list_of_lists, list):
        raise ValueError(f"Expected a list, got {type(maybe_list_of_lists)}")
    for entry in maybe_list_of_lists:
        if isinstance(entry, list):
            new_list.extend(entry)
        else:
            new_list.append(entry)
    return new_list
