"""A module with safe Python code — no secrets or sensitive data."""

import os
import sys
from datetime import datetime
from typing import Optional


def hello(name: str = "World") -> str:
    """Return a friendly greeting."""
    return f"Hello, {name}!"


class Foo:
    """A simple example class."""

    def __init__(self, value: int = 0) -> None:
        self._value = value

    def get_value(self) -> int:
        return self._value

    def set_value(self, value: int) -> None:
        self._value = value

    def __repr__(self) -> str:
        return f"Foo(value={self._value})"


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    print(hello())
    foo = Foo(42)
    print(foo)
