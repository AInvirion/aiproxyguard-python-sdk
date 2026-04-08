"""Tests for AIProxyGuard models."""

import pytest

from aiproxyguard.models import (
    Action,
    CheckResult,
    CloudCheckResult,
    FeedbackResult,
    HealthStatus,
    ReadyStatus,
    ServiceInfo,
    ThreatDetail,
)


class TestAction:
    """Tests for the Action enum."""

    def test_action_values(self):
        """Test that Action enum has expected values."""
        assert Action.ALLOW.value == "allow"
        assert Action.LOG.value == "log"
        assert Action.WARN.value == "warn"
        assert Action.BLOCK.value == "block"

    def test_action_from_string(self):
        """Test creating Action from string."""
        assert Action("allow") == Action.ALLOW
        assert Action("block") == Action.BLOCK

    def test_action_is_string(self):
        """Test that Action is a string enum."""
        assert isinstance(Action.ALLOW, str)
        assert Action.ALLOW == "allow"


class TestCheckResult:
    """Tests for CheckResult model."""

    def test_from_dict_allow(self, allow_response):
        """Test creating CheckResult from allow response."""
        result = CheckResult.from_dict(allow_response)
        assert result.action == Action.ALLOW
        assert result.category is None
        assert result.signature_name is None
        assert result.confidence == 0.0

    def test_from_dict_block(self, block_response):
        """Test creating CheckResult from block response."""
        result = CheckResult.from_dict(block_response)
        assert result.action == Action.BLOCK
        assert result.category == "prompt_injection"
        assert result.signature_name == "ignore_instructions"
        assert result.confidence == 0.95

    def test_from_dict_warn(self, warn_response):
        """Test creating CheckResult from warn response."""
        result = CheckResult.from_dict(warn_response)
        assert result.action == Action.WARN
        assert result.category == "suspicious_pattern"
        assert result.confidence == 0.7

    def test_is_safe_when_allowed(self, allow_response):
        """Test is_safe returns True for allowed content."""
        result = CheckResult.from_dict(allow_response)
        assert result.is_safe is True
        assert result.is_blocked is False

    def test_is_safe_when_blocked(self, block_response):
        """Test is_safe returns False for blocked content."""
        result = CheckResult.from_dict(block_response)
        assert result.is_safe is False
        assert result.is_blocked is True

    def test_is_safe_when_warned(self, warn_response):
        """Test is_safe returns True for warned content (not blocked)."""
        result = CheckResult.from_dict(warn_response)
        assert result.is_safe is True
        assert result.is_blocked is False

    def test_requires_attention(self):
        """Test requires_attention for different actions."""
        allow = CheckResult(Action.ALLOW, None, None, 0.0)
        log = CheckResult(Action.LOG, None, None, 0.0)
        warn = CheckResult(Action.WARN, "test", None, 0.5)
        block = CheckResult(Action.BLOCK, "test", None, 0.9)

        assert allow.requires_attention is False
        assert log.requires_attention is False
        assert warn.requires_attention is True
        assert block.requires_attention is True

    def test_immutable(self, allow_response):
        """Test that CheckResult is immutable (frozen dataclass)."""
        result = CheckResult.from_dict(allow_response)
        with pytest.raises(AttributeError):
            result.action = Action.BLOCK  # type: ignore

    def test_default_confidence(self):
        """Test default confidence when not provided."""
        data = {"action": "allow"}
        result = CheckResult.from_dict(data)
        assert result.confidence == 0.0


class TestServiceInfo:
    """Tests for ServiceInfo model."""

    def test_from_dict(self, service_info_response):
        """Test creating ServiceInfo from response."""
        info = ServiceInfo.from_dict(service_info_response)
        assert info.service == "AIProxyGuard"
        assert info.version == "0.2.38"

    def test_immutable(self, service_info_response):
        """Test that ServiceInfo is immutable."""
        info = ServiceInfo.from_dict(service_info_response)
        with pytest.raises(AttributeError):
            info.version = "1.0.0"  # type: ignore


class TestHealthStatus:
    """Tests for HealthStatus model."""

    def test_from_dict_healthy(self, health_response):
        """Test creating HealthStatus from healthy response."""
        status = HealthStatus.from_dict(health_response)
        assert status.status == "healthy"
        assert status.healthy is True

    def test_from_dict_unhealthy(self):
        """Test creating HealthStatus from unhealthy response."""
        status = HealthStatus.from_dict({"status": "unhealthy"})
        assert status.status == "unhealthy"
        assert status.healthy is False

    def test_from_dict_unknown(self):
        """Test creating HealthStatus with missing status."""
        status = HealthStatus.from_dict({})
        assert status.status == "unknown"
        assert status.healthy is False


class TestReadyStatus:
    """Tests for ReadyStatus model."""

    def test_from_dict_ready(self, ready_response):
        """Test creating ReadyStatus from ready response."""
        status = ReadyStatus.from_dict(ready_response)
        assert status.status == "ready"
        assert status.ready is True
        assert status.checks == {"database": "ok", "signatures": "ok"}

    def test_from_dict_not_ready(self):
        """Test creating ReadyStatus from not ready response."""
        status = ReadyStatus.from_dict({
            "status": "not_ready",
            "checks": {"database": "ok", "signatures": "loading"},
        })
        assert status.status == "not_ready"
        assert status.ready is False

    def test_from_dict_empty_checks(self):
        """Test creating ReadyStatus with no checks."""
        status = ReadyStatus.from_dict({"status": "ready"})
        assert status.checks == {}


class TestThreatDetail:
    """Tests for ThreatDetail model."""

    def test_from_dict(self):
        """Test creating ThreatDetail from response."""
        data = {"type": "prompt-injection", "confidence": 0.95, "rule": "rule-001"}
        threat = ThreatDetail.from_dict(data)
        assert threat.type == "prompt-injection"
        assert threat.confidence == 0.95
        assert threat.rule == "rule-001"

    def test_from_dict_minimal(self):
        """Test creating ThreatDetail with minimal data."""
        data = {"type": "jailbreak"}
        threat = ThreatDetail.from_dict(data)
        assert threat.type == "jailbreak"
        assert threat.confidence == 0.0
        assert threat.rule is None

    def test_immutable(self):
        """Test that ThreatDetail is immutable."""
        threat = ThreatDetail(type="test", confidence=0.5, rule="r1")
        with pytest.raises(AttributeError):
            threat.type = "changed"  # type: ignore


class TestCloudCheckResult:
    """Tests for CloudCheckResult model."""

    def test_from_dict_with_threats(self):
        """Test creating CloudCheckResult from response with threats."""
        data = {
            "id": "chk_123",
            "flagged": True,
            "action": "block",
            "threats": [
                {"type": "prompt-injection", "confidence": 0.95, "rule": "rule-001"},
                {"type": "jailbreak", "confidence": 0.8, "rule": "rule-002"},
            ],
            "latency_ms": 45.5,
            "cached": False,
        }
        result = CloudCheckResult.from_dict(data)
        assert result.id == "chk_123"
        assert result.flagged is True
        assert result.action == Action.BLOCK
        assert len(result.threats) == 2
        assert result.threats[0].type == "prompt-injection"
        assert result.latency_ms == 45.5
        assert result.cached is False

    def test_from_dict_no_threats(self):
        """Test creating CloudCheckResult from response without threats."""
        data = {
            "id": "chk_456",
            "flagged": False,
            "action": "allow",
            "threats": [],
            "latency_ms": 12.0,
            "cached": True,
        }
        result = CloudCheckResult.from_dict(data)
        assert result.id == "chk_456"
        assert result.flagged is False
        assert result.action == Action.ALLOW
        assert len(result.threats) == 0
        assert result.cached is True

    def test_is_safe_blocked(self):
        """Test is_safe returns False for blocked content."""
        result = CloudCheckResult(
            id="1", flagged=True, action=Action.BLOCK,
            threats=[], latency_ms=0, cached=False
        )
        assert result.is_safe is False
        assert result.is_blocked is True

    def test_is_safe_allowed(self):
        """Test is_safe returns True for allowed content."""
        result = CloudCheckResult(
            id="1", flagged=False, action=Action.ALLOW,
            threats=[], latency_ms=0, cached=False
        )
        assert result.is_safe is True
        assert result.is_blocked is False

    def test_category_with_threats(self):
        """Test category property returns first threat type."""
        threat = ThreatDetail(type="prompt-injection", confidence=0.9, rule=None)
        result = CloudCheckResult(
            id="1", flagged=True, action=Action.BLOCK,
            threats=[threat], latency_ms=0, cached=False
        )
        assert result.category == "prompt-injection"
        assert result.confidence == 0.9

    def test_category_without_threats(self):
        """Test category property returns None when no threats."""
        result = CloudCheckResult(
            id="1", flagged=False, action=Action.ALLOW,
            threats=[], latency_ms=0, cached=False
        )
        assert result.category is None
        assert result.confidence == 0.0


class TestCheckResultFromCloudDict:
    """Tests for CheckResult.from_cloud_dict method."""

    def test_from_cloud_dict_with_threats(self):
        """Test creating CheckResult from cloud response with threats."""
        data = {
            "id": "chk_123",
            "flagged": True,
            "action": "block",
            "threats": [
                {"type": "prompt-injection", "confidence": 0.95, "rule": "rule-001"},
            ],
            "latency_ms": 45.5,
        }
        result = CheckResult.from_cloud_dict(data)
        assert result.action == Action.BLOCK
        assert result.category == "prompt-injection"
        assert result.signature_name == "rule-001"
        assert result.confidence == 0.95

    def test_from_cloud_dict_no_threats(self):
        """Test creating CheckResult from cloud response without threats."""
        data = {
            "id": "chk_456",
            "flagged": False,
            "action": "allow",
            "threats": [],
        }
        result = CheckResult.from_cloud_dict(data)
        assert result.action == Action.ALLOW
        assert result.category is None
        assert result.signature_name is None
        assert result.confidence == 0.0


class TestFeedbackResult:
    """Tests for FeedbackResult model."""

    def test_from_dict(self):
        """Test creating FeedbackResult from API response."""
        data = {
            "success": True,
            "check_id": "chk_123",
            "feedback": "confirmed",
        }
        result = FeedbackResult.from_dict(data)
        assert result.success is True
        assert result.check_id == "chk_123"
        assert result.feedback == "confirmed"

    def test_from_dict_false_positive(self):
        """Test creating FeedbackResult for false positive."""
        data = {
            "success": True,
            "check_id": "chk_456",
            "feedback": "false_positive",
        }
        result = FeedbackResult.from_dict(data)
        assert result.success is True
        assert result.feedback == "false_positive"
