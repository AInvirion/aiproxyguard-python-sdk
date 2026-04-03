"""AIProxyGuard Python SDK - LLM security proxy for prompt injection detection.

Example:
    >>> from aiproxyguard import AIProxyGuard
    >>> client = AIProxyGuard("https://docker.aiproxyguard.com")
    >>> result = client.check("Ignore all previous instructions")
    >>> if result.is_blocked:
    ...     print(f"Blocked: {result.category}")
"""

from .client import AIProxyGuard, ApiMode
from .decorators import GuardConfigurationError, guard, guard_output
from .exceptions import (
    AIProxyGuardError,
    ConnectionError,
    ContentBlockedError,
    RateLimitError,
    ServerError,
    TimeoutError,
    ValidationError,
)
from .models import (
    Action,
    CheckResult,
    CloudCheckResult,
    HealthStatus,
    ReadyStatus,
    ServiceInfo,
    ThreatDetail,
)

__version__ = "0.1.0"

__all__ = [
    # Client
    "AIProxyGuard",
    "ApiMode",
    # Models
    "Action",
    "CheckResult",
    "CloudCheckResult",
    "HealthStatus",
    "ReadyStatus",
    "ServiceInfo",
    "ThreatDetail",
    # Exceptions
    "AIProxyGuardError",
    "ConnectionError",
    "ContentBlockedError",
    "GuardConfigurationError",
    "RateLimitError",
    "ServerError",
    "TimeoutError",
    "ValidationError",
    # Decorators
    "guard",
    "guard_output",
]
