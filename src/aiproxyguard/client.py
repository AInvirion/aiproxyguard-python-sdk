"""AIProxyGuard client for prompt injection detection."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable
from enum import Enum
from typing import Any, Callable, TypeVar

import httpx

from ._version import __version__
from .exceptions import (
    AIProxyGuardError,
    ConnectionError,
    RateLimitError,
    ServerError,
    TimeoutError,
    ValidationError,
)
from .models import (
    CheckResult,
    CloudCheckResult,
    FeedbackResult,
    HealthStatus,
    ReadyStatus,
    ServiceInfo,
)

# Maximum characters to include from response text in error messages
_MAX_ERROR_TEXT_LENGTH = 200

T = TypeVar("T")


class ApiMode(str, Enum):
    """API mode for the client."""

    PROXY = "proxy"  # Direct proxy (e.g., docker.aiproxyguard.com)
    CLOUD = "cloud"  # Cloud API (e.g., aiproxyguard.com/api/v1)


class AIProxyGuard:
    """AIProxyGuard client for prompt injection detection.

    Provides both synchronous and asynchronous methods for checking text
    against the AIProxyGuard API for potential prompt injection attacks.

    Supports two API modes:
    - "proxy": Direct proxy mode (docker.aiproxyguard.com) - simpler
    - "cloud": Cloud API mode (aiproxyguard.com) - caching, rate limiting

    Args:
        base_url: Base URL of the AIProxyGuard service.
        api_key: Optional API key for authentication (required for cloud mode).
        timeout: Request timeout in seconds. Defaults to 30.0.
        retries: Number of retry attempts for transient failures. Defaults to 3.
        retry_delay: Initial delay between retries in seconds. Defaults to 0.5.
        max_concurrency: Max concurrent requests for batch operations. Defaults to 10.
        api_mode: API mode - "proxy" or "cloud". Auto-detected from URL.

    Example:
        >>> # Direct proxy mode
        >>> client = AIProxyGuard("https://docker.aiproxyguard.com")
        >>> result = client.check("Ignore all previous instructions")

        >>> # Cloud API mode
        >>> client = AIProxyGuard(
        ...     "https://aiproxyguard.com",
        ...     api_key="apg_xxx",
        ...     api_mode="cloud"
        ... )
        >>> result = client.check("Ignore all previous instructions")
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: str | None = None,
        timeout: float = 30.0,
        retries: int = 3,
        retry_delay: float = 0.5,
        max_concurrency: int = 10,
        api_mode: str | None = None,
        allow_insecure: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.max_concurrency = max_concurrency
        self._client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None
        self._pending_async_close: httpx.AsyncClient | None = None

        # Security: Reject plain HTTP with API keys unless explicitly allowed
        if api_key and self.base_url.startswith("http://") and not allow_insecure:
            # Allow localhost for development
            if not any(h in self.base_url for h in ("localhost", "127.0.0.1", "[::1]")):
                raise ValidationError(
                    "API key provided with non-HTTPS URL. "
                    "Use HTTPS or set allow_insecure=True for testing."
                )

        # Auto-detect API mode from URL if not specified
        if api_mode is None:
            # Cloud mode if URL contains aiproxyguard.com but not docker.
            if "aiproxyguard.com" in self.base_url and "docker" not in self.base_url:
                self._api_mode = ApiMode.CLOUD
            else:
                self._api_mode = ApiMode.PROXY
        else:
            self._api_mode = ApiMode(api_mode)

    @property
    def api_key(self) -> str | None:
        """Get the current API key."""
        return self._api_key

    @property
    def api_mode(self) -> ApiMode:
        """Get the current API mode."""
        return self._api_mode

    def set_api_key(self, api_key: str | None) -> None:
        """Update the API key and rebuild HTTP clients.

        Args:
            api_key: New API key, or None to remove authentication.

        Note:
            If an async client exists, it will be scheduled for cleanup.
            Call aclose() or use the async context manager for proper cleanup.
        """
        self._api_key = api_key
        # Close existing clients so they get rebuilt with new headers
        if self._client is not None:
            self._client.close()
            self._client = None
        if self._async_client is not None:
            # Track for cleanup - will be closed on next aclose() or close()
            self._pending_async_close = self._async_client
            self._async_client = None

    def _get_headers(self) -> dict[str, str]:
        """Build request headers."""
        headers = {
            "Content-Type": "application/json",
            "X-SDK-Version": __version__,
            "X-SDK-Type": "python-sdk",
        }
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        return headers

    def _get_client(self) -> httpx.Client:
        """Get or create the sync HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=self._get_headers(),
                timeout=self.timeout,
            )
        return self._client

    def _get_async_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._get_headers(),
                timeout=self.timeout,
            )
        return self._async_client

    def _truncate_error_text(self, text: str) -> str:
        """Truncate response text for error messages to prevent log pollution."""
        if len(text) <= _MAX_ERROR_TEXT_LENGTH:
            return text
        return text[:_MAX_ERROR_TEXT_LENGTH] + "..."

    def _parse_retry_after(self, value: str | None) -> int | None:
        """Parse Retry-After header (integer seconds or HTTP-date)."""
        if not value:
            return None
        # Try integer seconds first (most common)
        try:
            return int(value)
        except ValueError:
            pass
        # Try HTTP-date format (e.g., "Wed, 21 Oct 2015 07:28:00 GMT")
        try:
            from email.utils import parsedate_to_datetime

            retry_dt = parsedate_to_datetime(value)
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc)
            delta = (retry_dt - now).total_seconds()
            return max(0, int(delta))
        except (ValueError, TypeError):
            # Invalid format, ignore
            return None

    def _handle_error(self, response: httpx.Response) -> None:
        """Handle error responses from the API."""
        if response.status_code == 429:
            retry_after = self._parse_retry_after(response.headers.get("Retry-After"))
            raise RateLimitError(
                "Rate limited",
                retry_after=retry_after,
            )

        # 5xx errors are server errors (retryable)
        if response.status_code >= 500:
            raise ServerError(
                f"Server error: HTTP {response.status_code}",
                status_code=response.status_code,
            )

        # 4xx errors are client errors (not retryable)
        if response.status_code >= 400:
            try:
                data = response.json()
                # Handle different error formats
                if "error" in data:
                    error = data["error"]
                    if isinstance(error, dict):
                        raise ValidationError(
                            error.get("message", "Unknown error"),
                            code=error.get("type"),
                        )
                    else:
                        raise ValidationError(str(error))
                elif "detail" in data:
                    # FastAPI style error
                    raise ValidationError(str(data["detail"]))
                else:
                    raise ValidationError(str(data))
            except (ValueError, KeyError, TypeError):
                error_text = self._truncate_error_text(response.text)
                raise AIProxyGuardError(f"HTTP {response.status_code}: {error_text}")

    def _get_check_endpoint(self) -> str:
        """Get the check endpoint based on API mode."""
        if self._api_mode == ApiMode.CLOUD:
            return "/api/v1/check"
        return "/check"

    def _build_check_payload(
        self, text: str, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Build the request payload based on API mode."""
        if self._api_mode == ApiMode.CLOUD:
            payload: dict[str, Any] = {"input": text}
            if context:
                payload["context"] = context
            return payload
        return {"text": text}

    def _parse_check_response(self, data: dict[str, Any]) -> CheckResult:
        """Parse check response based on API mode."""
        if self._api_mode == ApiMode.CLOUD:
            return CheckResult.from_cloud_dict(data)
        return CheckResult.from_dict(data)

    def _calculate_delay(self, attempt: int, rate_limit_retry: int | None) -> float:
        """Calculate delay with exponential backoff and jitter."""
        if rate_limit_retry is not None:
            return float(rate_limit_retry)
        base_delay: float = self.retry_delay * (2**attempt)
        jitter: float = random.uniform(0, 0.1 * base_delay)
        return base_delay + jitter

    def _retry_sync(self, operation: Callable[[], T]) -> T:
        """Execute operation with retry logic (sync)."""
        last_exception: Exception | None = None

        for attempt in range(self.retries + 1):
            try:
                return operation()

            except httpx.TimeoutException:
                last_exception = TimeoutError("Request timed out")
            except httpx.ConnectError:
                last_exception = ConnectionError("Failed to connect to AIProxyGuard")
            except RateLimitError as e:
                last_exception = e
                if attempt < self.retries:
                    time.sleep(self._calculate_delay(attempt, e.retry_after))
                continue
            except ServerError as e:
                last_exception = e
            except ValidationError:
                raise

            if attempt < self.retries:
                time.sleep(self._calculate_delay(attempt, None))

        raise last_exception or AIProxyGuardError("Request failed after retries")

    async def _retry_async(self, operation: Callable[[], Awaitable[T]]) -> T:
        """Execute operation with retry logic (async)."""
        last_exception: Exception | None = None

        for attempt in range(self.retries + 1):
            try:
                return await operation()

            except httpx.TimeoutException:
                last_exception = TimeoutError("Request timed out")
            except httpx.ConnectError:
                last_exception = ConnectionError("Failed to connect to AIProxyGuard")
            except RateLimitError as e:
                last_exception = e
                if attempt < self.retries:
                    await asyncio.sleep(self._calculate_delay(attempt, e.retry_after))
                continue
            except ServerError as e:
                last_exception = e
            except ValidationError:
                raise

            if attempt < self.retries:
                await asyncio.sleep(self._calculate_delay(attempt, None))

        raise last_exception or AIProxyGuardError("Request failed after retries")

    # -------------------------------------------------------------------------
    # Sync API
    # -------------------------------------------------------------------------

    def check(
        self, text: str, context: dict[str, Any] | None = None
    ) -> CheckResult:
        """Check text for prompt injection.

        Args:
            text: The text to scan for prompt injection.
            context: Optional context metadata (cloud mode only).

        Returns:
            CheckResult with action, category, signature_name, and confidence.

        Raises:
            ValidationError: If the request is invalid.
            TimeoutError: If the request times out.
            RateLimitError: If rate limited.
            ConnectionError: If connection fails.
            ServerError: If the server returns a 5xx error.
            AIProxyGuardError: For other errors.
        """
        client = self._get_client()
        endpoint = self._get_check_endpoint()
        payload = self._build_check_payload(text, context)

        def do_check() -> CheckResult:
            response = client.post(endpoint, json=payload)
            self._handle_error(response)
            return self._parse_check_response(response.json())

        return self._retry_sync(do_check)

    def check_cloud(
        self, text: str, context: dict[str, Any] | None = None
    ) -> CloudCheckResult:
        """Check text and return full cloud API response (cloud mode only).

        Args:
            text: The text to scan for prompt injection.
            context: Optional context metadata (e.g., {"provider": "openai"}).

        Returns:
            CloudCheckResult with full response including id, latency_ms, cached.

        Raises:
            AIProxyGuardError: If not in cloud mode or request fails.
        """
        if self._api_mode != ApiMode.CLOUD:
            raise AIProxyGuardError("check_cloud() requires cloud API mode")

        client = self._get_client()
        payload = self._build_check_payload(text, context)

        def do_check() -> CloudCheckResult:
            response = client.post("/api/v1/check", json=payload)
            self._handle_error(response)
            return CloudCheckResult.from_dict(response.json())

        return self._retry_sync(do_check)

    def feedback(
        self,
        check_id: str,
        feedback: str,
        comment: str | None = None,
    ) -> FeedbackResult:
        """Submit feedback for a check result (cloud mode only).

        Use this to report false positives or confirm correct detections,
        which helps improve detection accuracy over time.

        Args:
            check_id: The check ID from CloudCheckResult.id.
            feedback: Either "confirmed" (correct detection) or "false_positive".
            comment: Optional comment explaining the feedback.

        Returns:
            FeedbackResult confirming the feedback was recorded.

        Raises:
            AIProxyGuardError: If not in cloud mode or request fails.
            ValidationError: If check_id not found or invalid feedback value.
        """
        if self._api_mode != ApiMode.CLOUD:
            raise AIProxyGuardError("feedback() requires cloud API mode")

        if feedback not in ("confirmed", "false_positive"):
            raise ValidationError("feedback must be 'confirmed' or 'false_positive'")

        client = self._get_client()
        payload: dict[str, Any] = {"check_id": check_id, "feedback": feedback}
        if comment:
            payload["comment"] = comment

        def do_feedback() -> FeedbackResult:
            response = client.post("/api/v1/feedback", json=payload)
            self._handle_error(response)
            return FeedbackResult.from_dict(response.json())

        return self._retry_sync(do_feedback)

    def check_batch(self, texts: list[str]) -> list[CheckResult]:
        """Check multiple texts for prompt injection.

        Args:
            texts: List of texts to scan.

        Returns:
            List of CheckResult objects in the same order as inputs.
        """
        return [self.check(text) for text in texts]

    def is_safe(self, text: str) -> bool:
        """Check if text is safe (not blocked).

        Args:
            text: The text to scan.

        Returns:
            True if the text is safe, False if blocked.
        """
        return self.check(text).is_safe

    def info(self) -> ServiceInfo:
        """Get service information (proxy mode only).

        Returns:
            ServiceInfo with service name and version.

        Raises:
            AIProxyGuardError: If called in cloud mode.
        """
        if self._api_mode == ApiMode.CLOUD:
            raise AIProxyGuardError("info() is not available in cloud mode")
        client = self._get_client()
        response = client.get("/")
        self._handle_error(response)
        return ServiceInfo.from_dict(response.json())

    def health(self) -> HealthStatus:
        """Check service health.

        Returns:
            HealthStatus with health status.
        """
        client = self._get_client()
        endpoint = "/health" if self._api_mode == ApiMode.CLOUD else "/healthz"
        try:
            response = client.get(endpoint)
            if response.status_code == 200:
                return HealthStatus.from_dict(response.json())
            return HealthStatus(status="unhealthy", healthy=False)
        except Exception:
            return HealthStatus(status="unreachable", healthy=False)

    def ready(self) -> ReadyStatus:
        """Check service readiness (proxy mode only).

        Returns:
            ReadyStatus with readiness status and individual checks.

        Raises:
            AIProxyGuardError: If called in cloud mode.
        """
        if self._api_mode == ApiMode.CLOUD:
            raise AIProxyGuardError("ready() is not available in cloud mode")
        client = self._get_client()
        try:
            response = client.get("/readyz")
            return ReadyStatus.from_dict(response.json())
        except Exception:
            return ReadyStatus(status="unreachable", ready=False, checks={})

    # -------------------------------------------------------------------------
    # Async API
    # -------------------------------------------------------------------------

    async def check_async(
        self, text: str, context: dict[str, Any] | None = None
    ) -> CheckResult:
        """Async version of check().

        Args:
            text: The text to scan for prompt injection.
            context: Optional context metadata (cloud mode only).

        Returns:
            CheckResult with action, category, signature_name, and confidence.
        """
        client = self._get_async_client()
        endpoint = self._get_check_endpoint()
        payload = self._build_check_payload(text, context)

        async def do_check() -> CheckResult:
            response = await client.post(endpoint, json=payload)
            self._handle_error(response)
            return self._parse_check_response(response.json())

        return await self._retry_async(do_check)

    async def check_cloud_async(
        self, text: str, context: dict[str, Any] | None = None
    ) -> CloudCheckResult:
        """Async version of check_cloud()."""
        if self._api_mode != ApiMode.CLOUD:
            raise AIProxyGuardError("check_cloud_async() requires cloud API mode")

        client = self._get_async_client()
        payload = self._build_check_payload(text, context)

        async def do_check() -> CloudCheckResult:
            response = await client.post("/api/v1/check", json=payload)
            self._handle_error(response)
            return CloudCheckResult.from_dict(response.json())

        return await self._retry_async(do_check)

    async def feedback_async(
        self,
        check_id: str,
        feedback: str,
        comment: str | None = None,
    ) -> FeedbackResult:
        """Async version of feedback()."""
        if self._api_mode != ApiMode.CLOUD:
            raise AIProxyGuardError("feedback_async() requires cloud API mode")

        if feedback not in ("confirmed", "false_positive"):
            raise ValidationError("feedback must be 'confirmed' or 'false_positive'")

        client = self._get_async_client()
        payload: dict[str, Any] = {"check_id": check_id, "feedback": feedback}
        if comment:
            payload["comment"] = comment

        async def do_feedback() -> FeedbackResult:
            response = await client.post("/api/v1/feedback", json=payload)
            self._handle_error(response)
            return FeedbackResult.from_dict(response.json())

        return await self._retry_async(do_feedback)

    async def check_batch_async(
        self, texts: list[str], max_concurrency: int | None = None
    ) -> list[CheckResult]:
        """Async version of check_batch(). Runs checks with bounded concurrency.

        Args:
            texts: List of texts to scan.
            max_concurrency: Max concurrent requests. Uses client default if None.

        Returns:
            List of CheckResult objects in the same order as inputs.
        """
        limit = max_concurrency or self.max_concurrency
        semaphore = asyncio.Semaphore(limit)

        async def bounded_check(text: str) -> CheckResult:
            async with semaphore:
                return await self.check_async(text)

        tasks = [bounded_check(text) for text in texts]
        return await asyncio.gather(*tasks)

    async def is_safe_async(self, text: str) -> bool:
        """Async version of is_safe().

        Args:
            text: The text to scan.

        Returns:
            True if the text is safe, False if blocked.
        """
        result = await self.check_async(text)
        return result.is_safe

    async def info_async(self) -> ServiceInfo:
        """Async version of info()."""
        if self._api_mode == ApiMode.CLOUD:
            raise AIProxyGuardError("info_async() is not available in cloud mode")
        client = self._get_async_client()
        response = await client.get("/")
        self._handle_error(response)
        return ServiceInfo.from_dict(response.json())

    async def health_async(self) -> HealthStatus:
        """Async version of health()."""
        client = self._get_async_client()
        endpoint = "/health" if self._api_mode == ApiMode.CLOUD else "/healthz"
        try:
            response = await client.get(endpoint)
            if response.status_code == 200:
                return HealthStatus.from_dict(response.json())
            return HealthStatus(status="unhealthy", healthy=False)
        except Exception:
            return HealthStatus(status="unreachable", healthy=False)

    async def ready_async(self) -> ReadyStatus:
        """Async version of ready()."""
        if self._api_mode == ApiMode.CLOUD:
            raise AIProxyGuardError("ready_async() is not available in cloud mode")
        client = self._get_async_client()
        try:
            response = await client.get("/readyz")
            return ReadyStatus.from_dict(response.json())
        except Exception:
            return ReadyStatus(status="unreachable", ready=False, checks={})

    # -------------------------------------------------------------------------
    # Context Manager
    # -------------------------------------------------------------------------

    def __enter__(self) -> AIProxyGuard:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    async def __aenter__(self) -> AIProxyGuard:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    def _close_async_client_sync(self, client: httpx.AsyncClient) -> None:
        """Close an async client from a sync context."""
        if getattr(client, "_closed", True):
            return
        try:
            # If there's a running loop, schedule the close
            loop = asyncio.get_running_loop()
            loop.create_task(client.aclose())
        except RuntimeError:
            # No running loop - create a temporary one to close properly
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(client.aclose())
            finally:
                loop.close()

    def close(self) -> None:
        """Close all clients and release resources.

        Note:
            For async clients, this performs a best-effort synchronous close.
            Use aclose() in async contexts for proper cleanup.
        """
        if self._client:
            self._client.close()
            self._client = None
        # Close pending async client from set_api_key()
        if self._pending_async_close:
            self._close_async_client_sync(self._pending_async_close)
            self._pending_async_close = None
        # Close current async client if it exists
        if self._async_client:
            self._close_async_client_sync(self._async_client)
            self._async_client = None

    async def aclose(self) -> None:
        """Close all clients and release resources (async)."""
        # Close pending async client from set_api_key()
        if self._pending_async_close:
            await self._pending_async_close.aclose()
            self._pending_async_close = None
        # Close current async client
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None
        # Close sync client if it exists
        if self._client:
            self._client.close()
            self._client = None

    def __repr__(self) -> str:
        mode = self._api_mode.value
        return f"AIProxyGuard(base_url={self.base_url!r}, api_mode={mode!r})"
