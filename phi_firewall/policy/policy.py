"""Per-entity policy loaded from YAML."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

DEFAULT_POLICY = Path(__file__).with_name("default_policy.yaml")


class Action(str, Enum):
    TOKENIZE = "tokenize"
    MASK = "mask"
    BLOCK = "block"
    ALLOW = "allow"


@dataclass
class Policy:
    default: Action = Action.TOKENIZE
    entities: dict[str, Action] = field(default_factory=dict)

    def action_for(self, entity: str) -> Action:
        return self.entities.get(entity, self.default)


def load_policy(path: str | Path | None = None) -> Policy:
    raw = yaml.safe_load(Path(path or DEFAULT_POLICY).read_text())
    return Policy(
        default=Action(raw.get("default", "tokenize")),
        entities={k: Action(v) for k, v in (raw.get("entities") or {}).items()},
    )
