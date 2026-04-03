# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-03

### Added

- Initial release of the AIProxyGuard Python SDK
- `AIProxyGuard` client with sync and async support
- Support for both self-hosted and cloud API modes (`ApiMode.SELF_HOSTED`, `ApiMode.CLOUD`)
- Prompt injection detection via `check()` and `check_async()` methods
- `@guard` decorator for automatic input validation on functions
- `@guard_output` decorator for automatic output validation
- Comprehensive exception hierarchy:
  - `AIProxyGuardError` (base exception)
  - `ValidationError` for invalid inputs
  - `ConnectionError` for network issues
  - `TimeoutError` for request timeouts
  - `RateLimitError` for rate limit exceeded
  - `ServerError` for server-side errors
  - `ContentBlockedError` for blocked content
- Health check endpoints (`health()`, `ready()`, `info()`)
- Full type annotations and `py.typed` marker
- Support for Python 3.9, 3.10, 3.11, 3.12, and 3.13

[0.1.0]: https://github.com/AInvirion/aiproxyguard-python-sdk/releases/tag/v0.1.0
