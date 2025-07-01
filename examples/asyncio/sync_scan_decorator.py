from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.asyncio.scanner import Scanner as ScannerAsync
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.scan.models.content import Content

T = TypeVar("T")

AIRS_ALLOWED_RESPONSE: str = "allow"


def airs_scanning(
    scanner: Scanner | ScannerAsync,
    ai_profile: AiProfile,
    error_func: Callable | None = None,
) -> Callable[[...], T]:
    """
    Call this decorator to protect against malicious prompts

    Args:
        scanner: Instance of the Scanner class
        ai_profile: Use the right profile provided by the Security team
        error_func: Optional function to be called if user input isn't allowed

    Returns: Callable[T]

    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            content = kwargs.get("content")
            if not content:
                content = Content(prompt=kwargs.get("prompt"), response=kwargs.get("response"))

            scan_response = await scanner.sync_scan(ai_profile=ai_profile, content=content)
            is_blocked = scan_response.action != AIRS_ALLOWED_RESPONSE if scan_response else True

            if is_blocked and error_func:
                return await error_func(content.prompt)
            return await func(*args, **kwargs)

        return wrapper

    return decorator
