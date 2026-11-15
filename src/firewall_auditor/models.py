"""Models preserve evidence; they do not assert effective packet reachability."""
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Chain:
    family: str
    table: str
    name: str
    hook: str | None
    policy: str | None
    priority: Any


@dataclass(frozen=True)
class Rule:
    family: str
    table: str
    chain: str
    handle: int
    direction: str
    protocol: str | None
    source: Any
    destination: Any
    destination_port: Any
    action: str
    complete: bool
    expressions: list[dict]
    unsupported: list[dict]
    comment: str | None


@dataclass(frozen=True)
class Ruleset:
    chains: list[Chain]
    rules: list[Rule]
    raw: dict
    warnings: list[str]
