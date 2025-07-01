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

import os
from typing import Optional

from aisecurity.constants.base import (
    AI_SEC_API_ENDPOINT,
    AI_SEC_API_KEY,
    DEFAULT_ENDPOINT,
    MAX_API_KEY_LENGTH,
    MAX_NUMBER_OF_RETRIES,
)
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.logger import BaseLogger


class _Configuration(BaseLogger):
    def __init__(self):
        super().__init__()
        self._api_endpoint = DEFAULT_ENDPOINT
        self._api_key = None
        self._num_retries = MAX_NUMBER_OF_RETRIES

    def init(
        self,
        *,
        api_key: Optional[str] = None,
        api_endpoint: Optional[str] = None,
        num_retries: Optional[int] = None,
        **kwargs,
    ):
        deprecated_kwargs = ["project", "logger_level", "logger"]
        for dkwarg in deprecated_kwargs:
            if dkwarg in kwargs:
                raise DeprecationWarning(f"{dkwarg} keyword is no longer supported in aisecurity Configuration init()")

        self.logger.info(f"event={self.init.__name__} action=configuration_initialized")

        if api_endpoint:
            self.api_endpoint = api_endpoint
        elif api_endpoint := os.getenv(AI_SEC_API_ENDPOINT):
            self.api_endpoint = api_endpoint

        if api_key:
            self.api_key = api_key
        elif api_key := os.getenv(AI_SEC_API_KEY):
            self.api_key = api_key
        else:
            self._log_and_raise(
                "api_key can't be None",
                ErrorType.MISSING_VARIABLE,
            )

        if num_retries is not None:
            self.num_retries = num_retries

    def _log_and_raise(self, message, error_type):
        self.logger.error(f"event={self.init.__name__} {message}")
        raise AISecSDKException(message, error_type)

    @property
    def api_endpoint(self):
        return self._api_endpoint

    @api_endpoint.setter
    def api_endpoint(self, value):
        if value is None:
            value = DEFAULT_ENDPOINT
        self._api_endpoint = value
        self.logger.info(f"event={self.init.__name__} api_endpoint={self._api_endpoint} action=set")

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, value):
        if value is None or len(value) == 0:
            self._log_and_raise(
                "api_key can't be None",
                ErrorType.MISSING_VARIABLE,
            )
        if len(value) > MAX_API_KEY_LENGTH:
            self._log_and_raise(
                f"api_key can't exceed {MAX_API_KEY_LENGTH} bytes",
                ErrorType.AISEC_SDK_ERROR,
            )
        self._api_key = value
        self.logger.info(f"event={self.init.__name__} api_key value configured action=set")
        self.logger.debug(f"event={self.init.__name__} api_key_last8={self._api_key[:-8]}********* action=set")

    @property
    def num_retries(self):
        return self._num_retries

    @num_retries.setter
    def num_retries(self, value):
        if not isinstance(value, int):
            raise AISecSDKException(
                f"Invalid num_retries value: {value}. num_retries must be an integer.",
                ErrorType.AISEC_SDK_ERROR,
            )
        if value < 0:
            raise AISecSDKException(
                f"Invalid num_retries value: {value}. num_retries must be a non-negative integer.",
                ErrorType.AISEC_SDK_ERROR,
            )
        self._num_retries = value
        self.logger.info(f"event={self.init.__name__} var={self._num_retries} action=set")

    def reset(self):
        self._api_endpoint = DEFAULT_ENDPOINT
        self._api_key = None
        self._num_retries = MAX_NUMBER_OF_RETRIES
        self.logger.info(f"event={self.reset.__name__} action=configuration_reset")


# TODO: Move away global/singleton configuration
global_configuration = _Configuration()
