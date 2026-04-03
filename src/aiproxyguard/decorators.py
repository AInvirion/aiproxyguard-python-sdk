"""AIProxyGuard decorator utilities."""

from __future__ import annotations

import asyncio
import inspect
import warnings
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, Union, overload

from .exceptions import ContentBlockedError

if __import__("typing").TYPE_CHECKING:
    from .client import AIProxyGuard

F = TypeVar("F", bound=Callable[..., Any])


class GuardConfigurationError(ValueError):
    """Raised when the guard decorator is misconfigured."""

    pass


@overload
def guard(
    client: "AIProxyGuard",
    *,
    input_arg: str = "prompt",
    raise_on_block: bool = True,
    fail_closed: bool = True,
) -> Callable[[F], F]: ...


@overload
def guard(
    client: "AIProxyGuard",
    *,
    input_arg: int,
    raise_on_block: bool = True,
    fail_closed: bool = True,
) -> Callable[[F], F]: ...


def guard(
    client: "AIProxyGuard",
    *,
    input_arg: Union[str, int] = "prompt",
    raise_on_block: bool = True,
    fail_closed: bool = True,
) -> Callable[[F], F]:
    """Decorator to guard a function with prompt injection detection.

    Checks the specified input argument before the function executes.
    If the content is blocked and raise_on_block is True, raises ContentBlockedError.

    Args:
        client: AIProxyGuard client instance.
        input_arg: Name or index of the argument to check. Defaults to "prompt".
                   Can be a string (kwarg name) or int (positional index).
        raise_on_block: If True, raise ContentBlockedError when content is blocked.
                        If False, the function is not called but no error is raised.
        fail_closed: If True (default), raise GuardConfigurationError when input_arg
                     cannot be resolved. If False, issue a warning and skip checking.

    Returns:
        Decorated function that checks input before execution.

    Raises:
        GuardConfigurationError: If input_arg doesn't match any parameter (at decoration time
                                  for string args, or at call time if fail_closed=True).

    Example:
        >>> client = AIProxyGuard("http://localhost:8080")
        >>> @guard(client)
        ... def call_llm(prompt: str) -> str:
        ...     return "response"
        ...
        >>> @guard(client, input_arg="user_input")
        ... def process(user_input: str, system: str) -> str:
        ...     return "processed"
        ...
        >>> @guard(client, input_arg=0)
        ... def handle(text: str) -> str:
        ...     return "handled"
    """

    def decorator(func: F) -> F:
        is_async = asyncio.iscoroutinefunction(func)

        # Cache signature introspection at decoration time for performance
        sig = inspect.signature(func)
        param_names = list(sig.parameters.keys())

        # Validate string input_arg at decoration time
        if isinstance(input_arg, str):
            if input_arg not in param_names:
                raise GuardConfigurationError(
                    f"guard(): input_arg '{input_arg}' not found in function "
                    f"'{func.__name__}' parameters: {param_names}"
                )
            # Pre-compute the positional index for this parameter
            cached_arg_index: Optional[int] = param_names.index(input_arg)
        else:
            cached_arg_index = None

        def _extract_text(args: tuple, kwargs: dict) -> Optional[str]:
            """Extract text to check from function arguments."""
            text: Any = None
            resolved = False

            if isinstance(input_arg, int):
                if len(args) > input_arg:
                    text = args[input_arg]
                    resolved = True
                elif fail_closed:
                    raise GuardConfigurationError(
                        f"guard(): input_arg index {input_arg} out of range. "
                        f"Function '{func.__name__}' called with {len(args)} positional args."
                    )
                else:
                    warnings.warn(
                        f"guard(): input_arg index {input_arg} out of range for "
                        f"'{func.__name__}'. Skipping security check.",
                        RuntimeWarning,
                        stacklevel=4,
                    )
            else:
                # String input_arg - use cached index
                if input_arg in kwargs:
                    text = kwargs[input_arg]
                    resolved = True
                elif cached_arg_index is not None and cached_arg_index < len(args):
                    text = args[cached_arg_index]
                    resolved = True
                else:
                    # This shouldn't happen if validation passed, but handle edge cases
                    if fail_closed:
                        raise GuardConfigurationError(
                            f"guard(): Could not resolve input_arg '{input_arg}' "
                            f"for function '{func.__name__}'."
                        )
                    else:
                        warnings.warn(
                            f"guard(): Could not resolve '{input_arg}' for "
                            f"'{func.__name__}'. Skipping security check.",
                            RuntimeWarning,
                            stacklevel=4,
                        )

            if not resolved:
                return None

            return str(text) if text is not None else ""

        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            text = _extract_text(args, kwargs)

            # Check even empty strings (text is not None means we resolved the arg)
            if text is not None:
                result = client.check(text)
                if result.is_blocked:
                    if raise_on_block:
                        raise ContentBlockedError(result)
                    return None

            return func(*args, **kwargs)

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            text = _extract_text(args, kwargs)

            # Check even empty strings (text is not None means we resolved the arg)
            if text is not None:
                result = await client.check_async(text)
                if result.is_blocked:
                    if raise_on_block:
                        raise ContentBlockedError(result)
                    return None

            return await func(*args, **kwargs)

        return async_wrapper if is_async else sync_wrapper  # type: ignore[return-value]

    return decorator


def guard_output(
    client: "AIProxyGuard",
    *,
    raise_on_block: bool = True,
) -> Callable[[F], F]:
    """Decorator to guard a function's output with prompt injection detection.

    Checks the function's return value after execution.
    Useful for validating LLM responses before returning them.

    Args:
        client: AIProxyGuard client instance.
        raise_on_block: If True, raise ContentBlockedError when content is blocked.
                        If False, returns None instead of the blocked content.

    Returns:
        Decorated function that checks output after execution.

    Example:
        >>> client = AIProxyGuard("http://localhost:8080")
        >>> @guard_output(client)
        ... def get_llm_response(prompt: str) -> str:
        ...     return llm.generate(prompt)
    """

    def decorator(func: F) -> F:
        is_async = asyncio.iscoroutinefunction(func)

        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            output = func(*args, **kwargs)

            if output is not None:
                result = client.check(str(output))
                if result.is_blocked:
                    if raise_on_block:
                        raise ContentBlockedError(result)
                    return None

            return output

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            output = await func(*args, **kwargs)

            if output is not None:
                result = await client.check_async(str(output))
                if result.is_blocked:
                    if raise_on_block:
                        raise ContentBlockedError(result)
                    return None

            return output

        return async_wrapper if is_async else sync_wrapper  # type: ignore[return-value]

    return decorator
