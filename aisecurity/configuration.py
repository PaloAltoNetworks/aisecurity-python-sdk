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
import warnings

from aisecurity.constants.base import (
    AI_SEC_API_ENDPOINT,
    AI_SEC_API_KEY,
    AI_SEC_API_TOKEN,
    AI_SEC_CA_CERT,
    AI_SEC_CLIENT_CERT,
    AI_SEC_CLIENT_KEY,
    AI_SEC_PROXY,
    AI_SEC_TLS_VERIFY,
    DEFAULT_ENDPOINT,
    HEADER_API_KEY,
    HEADER_AUTH_TOKEN,
    MAX_API_KEY_LENGTH,
    MAX_NUMBER_OF_RETRIES,
    MAX_TOKEN_LENGTH,
)
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.logger import BaseLogger

# Header names the SDK manages itself for authentication. Callers may not
# override these via custom headers, as doing so would break authentication.
_RESERVED_HEADERS = {HEADER_API_KEY.lower(), HEADER_AUTH_TOKEN.lower()}

# Accepted string forms for the PANW_AI_SEC_TLS_VERIFY environment variable.
_ENV_VERIFY_TRUE = {"true", "1", "yes", "on"}
_ENV_VERIFY_FALSE = {"false", "0", "no", "off"}


def _parse_env_verify(raw: str):
    """Interpret the TLS-verify env var as a bool, else treat it as a CA path."""
    low = raw.strip().lower()
    if low in _ENV_VERIFY_TRUE:
        return True
    if low in _ENV_VERIFY_FALSE:
        return False
    return raw

if not (isinstance(DEFAULT_ENDPOINT, str) and DEFAULT_ENDPOINT.startswith("https://")):
    raise AISecSDKException(
        f"aisecurity.constants.base.DEFAULT_ENDPOINT must be an https:// URL (got: {DEFAULT_ENDPOINT!r})",
        ErrorType.AISEC_SDK_ERROR,
    )


class _Configuration(BaseLogger):
    def __init__(self):
        super().__init__()
        self._api_endpoint = DEFAULT_ENDPOINT
        self._api_key = None
        self._api_token = None
        self._num_retries = MAX_NUMBER_OF_RETRIES
        # Transport / TLS options (requests-style).
        self._verify = True
        self._ssl_ca_cert = None
        self._cert_file = None
        self._key_file = None
        self._custom_headers = {}
        self._proxy = None
        self._proxy_headers = None

    def init(
        self,
        *,
        api_key: str | None = None,
        api_token: str | None = None,
        api_endpoint: str | None = None,
        num_retries: int | None = None,
        verify: bool | str | None = None,
        cert: str | tuple[str, str] | None = None,
        headers: dict[str, str] | None = None,
        proxy: str | None = None,
        proxy_headers: dict[str, str] | None = None,
    ):
        """Initialise the global SDK configuration.

        Transport options mirror the ``requests`` library:

        * ``verify`` -- ``True`` (default) to verify TLS against system CAs,
          ``False`` to disable verification, or a path to a CA bundle.
        * ``cert`` -- path to a client certificate, or an
          ``(cert_path, key_path)`` tuple for a separate private key (mTLS).
        * ``headers`` -- a mapping of extra HTTP headers sent on every request.
        * ``proxy`` / ``proxy_headers`` -- an outbound proxy URL and optional
          headers to send to the proxy.

        Each option also has an environment-variable fallback:
        ``PANW_AI_SEC_TLS_VERIFY``, ``PANW_AI_SEC_CA_CERT``,
        ``PANW_AI_SEC_CLIENT_CERT`` (+ ``PANW_AI_SEC_CLIENT_KEY``) and
        ``PANW_AI_SEC_PROXY``.
        """
        if api_endpoint:
            self.api_endpoint = api_endpoint
        elif api_endpoint := os.getenv(AI_SEC_API_ENDPOINT):
            self.api_endpoint = api_endpoint

        if api_key:
            self.api_key = api_key
        elif api_key := os.getenv(AI_SEC_API_KEY):
            self.api_key = api_key

        if api_token:
            self.api_token = api_token
        elif api_token := os.getenv(AI_SEC_API_TOKEN):
            self.api_token = api_token

        if not (self.api_key or self.api_token):
            self._log_and_raise(
                "Either api_key or api_token must be provided ",
                ErrorType.MISSING_VARIABLE,
            )

        if num_retries is not None:
            self.num_retries = num_retries

        # TLS verification: explicit kwarg > TLS_VERIFY env > CA_CERT env.
        if verify is not None:
            self.verify = verify
        elif (env_verify := os.getenv(AI_SEC_TLS_VERIFY)) is not None:
            self.verify = _parse_env_verify(env_verify)
        elif env_ca := os.getenv(AI_SEC_CA_CERT):
            self.verify = env_ca

        # Client certificate (mTLS): explicit kwarg > CLIENT_CERT (+ KEY) env.
        if cert is not None:
            self.cert = cert
        elif env_cert := os.getenv(AI_SEC_CLIENT_CERT):
            env_key = os.getenv(AI_SEC_CLIENT_KEY)
            self.cert = (env_cert, env_key) if env_key else env_cert

        if headers is not None:
            self.headers = headers

        if proxy is not None:
            self.proxy = proxy
        elif env_proxy := os.getenv(AI_SEC_PROXY):
            self.proxy = env_proxy

        if proxy_headers is not None:
            self.proxy_headers = proxy_headers

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
        if not isinstance(value, str):
            self._log_and_raise(
                "api_endpoint must be a string starting with https://",
                ErrorType.AISEC_SDK_ERROR,
            )
        normalised = value.strip()
        if not normalised.lower().startswith("https://"):
            scheme = normalised.split("://", 1)[0] if "://" in normalised else "<none>"
            self._log_and_raise(
                f"api_endpoint must use the https:// scheme to protect credentials in transit (got scheme={scheme!r})",
                ErrorType.AISEC_SDK_ERROR,
            )
        self._api_endpoint = normalised
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

        if self.api_token:
            warnings.warn("Both API key and OAuth token are configured. Consider using only one authentication method.")

        self._api_key = value
        self.logger.info(f"event={self.init.__name__} api_key value configured action=set")
        self.logger.debug(f"event={self.init.__name__} api_key_last8=*********{self._api_key[-8:]} action=set")

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

    @property
    def api_token(self):
        return self._api_token

    @api_token.setter
    def api_token(self, value):
        if value is None or len(value) == 0:
            self._log_and_raise(
                "api_token can't be None",
                ErrorType.MISSING_VARIABLE,
            )
        if len(value) > MAX_TOKEN_LENGTH:
            self._log_and_raise(
                f"api_token can't exceed {MAX_TOKEN_LENGTH} bytes",
                ErrorType.AISEC_SDK_ERROR,
            )
        if self.api_key:
            warnings.warn("Both API key and OAuth token are configured. Consider using only one authentication method.")

        self._api_token = value
        self.logger.info(f"event={self.init.__name__} api_token value configured action=set")
        self.logger.debug(f"event={self.init.__name__} api_token_last8=*********{self._api_token[-8:]} action=set")

    @staticmethod
    def _require_file(path, label):
        if not isinstance(path, str) or not path:
            raise AISecSDKException(
                f"{label} must be a non-empty file path string",
                ErrorType.AISEC_SDK_ERROR,
            )
        if not os.path.isfile(path):
            raise AISecSDKException(
                f"{label} not found: {path}",
                ErrorType.AISEC_SDK_ERROR,
            )
        return path

    @property
    def verify(self):
        """requests-style verify: True/False or a CA-bundle path."""
        return self._verify

    @verify.setter
    def verify(self, value):
        if isinstance(value, bool):
            self._verify = value
            self._ssl_ca_cert = None
        elif isinstance(value, str):
            self._verify = self._require_file(value, "verify (CA bundle)")
            self._ssl_ca_cert = self._verify
        else:
            self._log_and_raise(
                "verify must be a bool or a path to a CA bundle",
                ErrorType.AISEC_SDK_ERROR,
            )
        if self._verify is False:
            warnings.warn(
                "TLS certificate verification is disabled (verify=False). "
                "This exposes credentials and traffic to interception; use only for testing."
            )
        self.logger.info(f"event={self.init.__name__} verify_ssl={self.verify_ssl} action=set")

    @property
    def verify_ssl(self):
        """Boolean derived from ``verify`` for the transport layer."""
        return self._verify is not False

    @property
    def ssl_ca_cert(self):
        return self._ssl_ca_cert

    @property
    def cert(self):
        """requests-style client cert: a path or an (cert, key) tuple."""
        if self._cert_file and self._key_file:
            return (self._cert_file, self._key_file)
        return self._cert_file

    @cert.setter
    def cert(self, value):
        if isinstance(value, str):
            self._cert_file = self._require_file(value, "cert")
            self._key_file = None
        elif isinstance(value, (tuple, list)) and len(value) == 2:
            self._cert_file = self._require_file(value[0], "cert (certificate)")
            self._key_file = self._require_file(value[1], "cert (private key)")
        else:
            self._log_and_raise(
                "cert must be a file path or a (cert_path, key_path) tuple",
                ErrorType.AISEC_SDK_ERROR,
            )
        self.logger.info(f"event={self.init.__name__} client_cert configured action=set")

    @property
    def cert_file(self):
        return self._cert_file

    @property
    def key_file(self):
        return self._key_file

    @property
    def headers(self):
        return dict(self._custom_headers)

    @headers.setter
    def headers(self, value):
        if not isinstance(value, dict):
            self._log_and_raise(
                "headers must be a dict of str -> str",
                ErrorType.AISEC_SDK_ERROR,
            )
        cleaned = {}
        for name, header_value in value.items():
            if not isinstance(name, str) or not isinstance(header_value, str):
                self._log_and_raise(
                    "headers must be a dict of str -> str",
                    ErrorType.AISEC_SDK_ERROR,
                )
            if name.lower() in _RESERVED_HEADERS:
                warnings.warn(
                    f"Header '{name}' is managed by the SDK for authentication and will be ignored."
                )
                continue
            cleaned[name] = header_value
        self._custom_headers = cleaned
        # Log header names only -- values may contain secrets.
        self.logger.info(
            f"event={self.init.__name__} custom_headers={sorted(cleaned)} action=set"
        )

    @property
    def custom_headers(self):
        return dict(self._custom_headers)

    @property
    def proxy(self):
        return self._proxy

    @proxy.setter
    def proxy(self, value):
        if not isinstance(value, str) or not value:
            self._log_and_raise(
                "proxy must be a non-empty URL string",
                ErrorType.AISEC_SDK_ERROR,
            )
        self._proxy = value
        self.logger.info(f"event={self.init.__name__} proxy={self._proxy} action=set")

    @property
    def proxy_headers(self):
        return dict(self._proxy_headers) if self._proxy_headers else None

    @proxy_headers.setter
    def proxy_headers(self, value):
        if not isinstance(value, dict):
            self._log_and_raise(
                "proxy_headers must be a dict of str -> str",
                ErrorType.AISEC_SDK_ERROR,
            )
        self._proxy_headers = dict(value)
        self.logger.info(
            f"event={self.init.__name__} proxy_headers={sorted(self._proxy_headers)} action=set"
        )

    def reset(self):
        self._api_endpoint = DEFAULT_ENDPOINT
        self._api_key = None
        self._api_token = None
        self._num_retries = MAX_NUMBER_OF_RETRIES
        self._verify = True
        self._ssl_ca_cert = None
        self._cert_file = None
        self._key_file = None
        self._custom_headers = {}
        self._proxy = None
        self._proxy_headers = None
        self.logger.info(f"event={self.reset.__name__} action=configuration_reset")


# TODO: Move away global/singleton configuration
global_configuration = _Configuration()
