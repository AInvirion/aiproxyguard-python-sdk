"""AIProxyGuard SDK data models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Action(str, Enum):
    """Action taken by AIProxyGuard on scanned content."""

    ALLOW = "allow"
    LOG = "log"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class ThreatDetail:
    """Details about a detected threat (cloud API only).

    Attributes:
        type: Threat category (e.g., "prompt-injection").
        confidence: Detection confidence (0.0 to 1.0).
        rule: Rule/signature ID that triggered the detection.
    """

    type: str
    confidence: float
    rule: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThreatDetail:
        """Create ThreatDetail from API response dictionary."""
        return cls(
            type=data["type"],
            confidence=float(data.get("confidence", 0.0)),
            rule=data.get("rule"),
        )


@dataclass(frozen=True)
class CheckResult:
    """Result from scanning text for prompt injection.

    Attributes:
        action: The action taken (allow, log, warn, or block).
        category: Category of the detected threat, if any.
        signature_name: Name of the matching signature, if any.
        confidence: Confidence score of the detection (0.0 to 1.0).
    """

    action: Action
    category: str | None
    signature_name: str | None
    confidence: float

    @property
    def is_safe(self) -> bool:
        """Returns True if the text was not blocked."""
        return self.action != Action.BLOCK

    @property
    def is_blocked(self) -> bool:
        """Returns True if the text was blocked."""
        return self.action == Action.BLOCK

    @property
    def requires_attention(self) -> bool:
        """Returns True if the text requires attention (warn or block)."""
        return self.action in (Action.WARN, Action.BLOCK)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckResult:
        """Create a CheckResult from a proxy API response dictionary."""
        return cls(
            action=Action(data["action"]),
            category=data.get("category"),
            signature_name=data.get("signature_name"),
            confidence=float(data.get("confidence", 0.0)),
        )

    @classmethod
    def from_cloud_dict(cls, data: dict[str, Any]) -> CheckResult:
        """Create a CheckResult from a cloud API response dictionary.

        The cloud API returns a different format with threats array.
        """
        threats = data.get("threats", [])
        category = None
        signature_name = None
        confidence = 0.0

        if threats:
            # Use the first threat for backwards compatibility
            first_threat = threats[0]
            category = first_threat.get("type")
            signature_name = first_threat.get("rule")
            confidence = float(first_threat.get("confidence", 0.0))

        return cls(
            action=Action(data["action"]),
            category=category,
            signature_name=signature_name,
            confidence=confidence,
        )


@dataclass(frozen=True)
class CloudCheckResult:
    """Extended result from the cloud API with additional metadata.

    Attributes:
        id: Unique check ID.
        flagged: Whether any threat was detected.
        action: The action taken (allow, log, warn, or block).
        threats: List of detected threats.
        latency_ms: Processing time in milliseconds.
        cached: Whether result was served from cache.
    """

    id: str
    flagged: bool
    action: Action
    threats: list[ThreatDetail]
    latency_ms: float
    cached: bool

    @property
    def is_safe(self) -> bool:
        """Returns True if the text was not blocked."""
        return self.action != Action.BLOCK

    @property
    def is_blocked(self) -> bool:
        """Returns True if the text was blocked."""
        return self.action == Action.BLOCK

    @property
    def category(self) -> str | None:
        """Returns the primary threat category, if any."""
        return self.threats[0].type if self.threats else None

    @property
    def confidence(self) -> float:
        """Returns the primary threat confidence."""
        return self.threats[0].confidence if self.threats else 0.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CloudCheckResult:
        """Create CloudCheckResult from API response dictionary."""
        return cls(
            id=data["id"],
            flagged=data["flagged"],
            action=Action(data["action"]),
            threats=[ThreatDetail.from_dict(t) for t in data.get("threats", [])],
            latency_ms=float(data.get("latency_ms", 0.0)),
            cached=data.get("cached", False),
        )


@dataclass(frozen=True)
class ServiceInfo:
    """Service information from the AIProxyGuard API.

    Attributes:
        service: Service name.
        version: Service version.
    """

    service: str
    version: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServiceInfo:
        """Create ServiceInfo from an API response dictionary."""
        return cls(service=data["service"], version=data["version"])


@dataclass(frozen=True)
class HealthStatus:
    """Health status from the AIProxyGuard API.

    Attributes:
        status: Health status string (e.g., "healthy").
        healthy: Boolean indicating if the service is healthy.
    """

    status: str
    healthy: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HealthStatus:
        """Create HealthStatus from an API response dictionary."""
        status = data.get("status", "unknown")
        return cls(status=status, healthy=status == "healthy")


@dataclass(frozen=True)
class ReadyStatus:
    """Readiness status from the AIProxyGuard API.

    Attributes:
        status: Readiness status string (e.g., "ready").
        ready: Boolean indicating if the service is ready.
        checks: Dictionary of individual check results.
    """

    status: str
    ready: bool
    checks: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReadyStatus:
        """Create ReadyStatus from an API response dictionary."""
        status = data.get("status", "unknown")
        return cls(
            status=status,
            ready=status == "ready",
            checks=data.get("checks", {}),
        )
