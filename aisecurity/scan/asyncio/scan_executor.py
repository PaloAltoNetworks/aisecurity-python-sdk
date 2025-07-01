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

import aiohttp
from singleton_decorator import singleton

from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.generated_openapi_client import (
    AiProfile,
    ScanRequest,
    ScanRequestContentsInner,
    ScanResponse,
)
from aisecurity.generated_openapi_client.asyncio.exceptions import ApiException
from aisecurity.generated_openapi_client.models.metadata import Metadata
from aisecurity.scan.asyncio.base import ScanApiBase
from aisecurity.scan.models.content import Content


@singleton
class ScanExecutor(ScanApiBase):
    def __init__(self):
        """
        Initialize the ScanExecutor with the ScansApi client.
        """
        super().__init__()

    async def sync_request(
        self, content: Content, ai_profile: AiProfile, tr_id: str, metadata: Metadata
    ) -> ScanResponse:
        """
        Create and execute a synchronous scan request.

        Args:
            content (Content): The content to be scanned.
            ai_profile (AiProfile): The AI profile to be used for scanning.
            tr_id (str): Optionally Provide any unique identifier string for correlating the prompt and response transactions. This is an optional field. The tr_id value received for scan request is returned in the scan response along with the scan ID
            metadata (Metadata): Optionally send the app_name, app_user, and ai_model in the metadata

        Returns:
            ScanResponse: The response from the synchronous scan request.
        """
        try:
            return await self.scan_api.scan_sync_request(
                scan_request=ScanRequest(
                    tr_id=tr_id,
                    contents=[
                        ScanRequestContentsInner(
                            prompt=content.prompt,
                            response=content.response,
                            context=content.context,
                            code_prompt=content.code_prompt,
                            code_response=content.code_response,
                        )
                    ],
                    ai_profile=ai_profile,
                    metadata=metadata,
                ),
            )
        except ApiException as e:
            """
                Handle API exceptions that may occur during the API call
            """
            self.logger.error(f"event={self.sync_request.__name__} error={e}")
            raise AISecSDKException(str(e), ErrorType.SERVER_SIDE_ERROR)
        except aiohttp.ClientError as e:
            """
                A catch-all for other client-side exceptions that may occur during the API call
            """
            self.logger.error(f"event={self.sync_request.__name__} error={e}")
            raise AISecSDKException(str(e), ErrorType.CLIENT_SIDE_ERROR)
        except Exception as e:
            self.logger.error(f"event={self.sync_request.__name__} error={e}")
            raise AISecSDKException(str(e))
