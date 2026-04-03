"""AIProxyGuard SDK exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import CheckResult


class AIProxyGuardError(Exception):
    """Base exception for AIProxyGuard SDK."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code

    def __repr__(self) -> str:
        cls = self.__class__.__name__
        return f"{cls}(message={self.message!r}, code={self.code!r})"


class ValidationError(AIProxyGuardError):
    """Raised when the request is invalid (400 errors)."""

    pass


class ConnectionError(AIProxyGuardError):
    """Raised when connection to the service fails."""

    pass


class TimeoutError(AIProxyGuardError):
    """Raised when a request times out."""

    pass


class ServerError(AIProxyGuardError):
    """Raised when the server returns a 5xx error (retryable)."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message, code="server_error")
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"ServerError(status_code={self.status_code}, message={self.message!r})"


class RateLimitError(AIProxyGuardError):
    """Raised when rate limited (429 errors)."""

    def __init__(
        self, message: str = "Rate limited", retry_after: int | None = None
    ) -> None:
        super().__init__(message, code="rate_limit")
        self.retry_after = retry_after

    def __repr__(self) -> str:
        return f"RateLimitError(message={self.message!r}, retry={self.retry_after})"


class ContentBlockedError(AIProxyGuardError):
    """Raised when content is blocked due to prompt injection detection."""

    def __init__(self, result: CheckResult) -> None:
        super().__init__(f"Content blocked: {result.category}", code="content_blocked")
        self.result = result

    def __repr__(self) -> str:
        cat = self.result.category
        conf = self.result.confidence
        return f"ContentBlockedError(category={cat!r}, confidence={conf})"
