"""Pytest configuration and fixtures for AIProxyGuard tests."""

import pytest
import respx


@pytest.fixture
def base_url() -> str:
    """Base URL for tests (uses proxy mode)."""
    return "https://test-proxy.example.com"


@pytest.fixture
def mock_api(base_url: str):
    """Mock API responses using respx."""
    with respx.mock(base_url=base_url, assert_all_called=False) as respx_mock:
        yield respx_mock


@pytest.fixture
def allow_response() -> dict:
    """Response for safe content."""
    return {
        "action": "allow",
        "category": None,
        "signature_name": None,
        "confidence": 0.0,
    }


@pytest.fixture
def block_response() -> dict:
    """Response for blocked content."""
    return {
        "action": "block",
        "category": "prompt_injection",
        "signature_name": "ignore_instructions",
        "confidence": 0.95,
    }


@pytest.fixture
def warn_response() -> dict:
    """Response for warned content."""
    return {
        "action": "warn",
        "category": "suspicious_pattern",
        "signature_name": "encoded_payload",
        "confidence": 0.7,
    }


@pytest.fixture
def service_info_response() -> dict:
    """Service info response."""
    return {
        "service": "AIProxyGuard",
        "version": "0.2.38",
    }


@pytest.fixture
def health_response() -> dict:
    """Health check response."""
    return {"status": "healthy"}


@pytest.fixture
def ready_response() -> dict:
    """Readiness check response."""
    return {
        "status": "ready",
        "checks": {
            "database": "ok",
            "signatures": "ok",
        },
    }


@pytest.fixture
def validation_error_response() -> dict:
    """Validation error response."""
    return {
        "error": {
            "type": "invalid_request",
            "message": "Text field is required",
        }
    }
