"""Checks on Pydantic JSON schemas shared by model tests."""

from typing import Any


def free_string_paths(schema: Any, path: str = "#") -> list[str]:
    """JSON-schema paths of string fields that accept arbitrary text: no
    pattern, no enum, no const. For models that must never carry
    attacker-chosen text (token names, revert reasons) to the verifier."""
    found: list[str] = []
    if isinstance(schema, dict):
        if (
            schema.get("type") == "string"
            and "pattern" not in schema
            and "enum" not in schema
            and "const" not in schema
        ):
            found.append(path)
        for key, child in schema.items():
            found += free_string_paths(child, f"{path}/{key}")
    elif isinstance(schema, list):
        for i, child in enumerate(schema):
            found += free_string_paths(child, f"{path}/{i}")
    return found
