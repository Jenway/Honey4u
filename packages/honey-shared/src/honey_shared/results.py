from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Success[T]:
    value: T


@dataclass
class Failure:
    error_code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


type Result[T] = Success[T] | Failure


def success[T](value: T) -> Success[T]:
    return Success(value)


def failure(error_code: str, message: str, details: dict[str, Any] | None = None) -> Failure:
    return Failure(error_code=error_code, message=message, details=details or {})
