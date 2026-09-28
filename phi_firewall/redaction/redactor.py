"""Replace sensitive spans with tokens, and put them back later.

    "Patient: Jane Doe, DOB 04/12/1987, email jane@x.com"
 -> "Patient: [[PERSON_1]], DOB [[DOB_1]], email [[EMAIL_1]]"

The same value always gets the same token within a request, so the LLM can
still reason ("[[PERSON_1]] is allergic ... [[PERSON_1]] should avoid ...").
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from ..detectors import DetectionEngine
from ..policy import Action, Policy

TOKEN_RE = re.compile(r"\[\[([A-Z_]+_\d+)\]\]")


class BlockedContent(Exception):
    def __init__(self, entities: list[str]):
        super().__init__(f"request blocked by policy: contains {', '.join(sorted(set(entities)))}")
        self.entities = entities


@dataclass
class RedactionResult:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)   # token -> original value
    counts: Counter = field(default_factory=Counter)         # entity -> how many found


class Redactor:
    def __init__(self, engine: DetectionEngine, policy: Policy):
        self.engine = engine
        self.policy = policy

    def redact(self, text: str, mapping: dict[str, str] | None = None,
               counts: Counter | None = None) -> RedactionResult:
        """Redact one string. Pass the same `mapping` for every message in a
        request so tokens stay consistent across the conversation."""
        mapping = mapping if mapping is not None else {}
        counts = counts if counts is not None else Counter()
        reverse = {v: k for k, v in mapping.items()}
        spans = self.engine.detect(text)

        blocked = [s.entity for s in spans if self.policy.action_for(s.entity) == Action.BLOCK]
        if blocked:
            raise BlockedContent(blocked)

        out, pos = [], 0
        for s in spans:
            action = self.policy.action_for(s.entity)
            if action == Action.ALLOW:
                continue
            counts[s.entity] += 1
            out.append(text[pos:s.start])
            if action == Action.MASK:
                out.append(f"[{s.entity}]")
            else:  # TOKENIZE
                token = reverse.get(s.text)
                if token is None:
                    n = sum(1 for t in mapping if t.startswith(s.entity + "_")) + 1
                    token = f"{s.entity}_{n}"
                    mapping[token] = s.text
                    reverse[s.text] = token
                out.append(f"[[{token}]]")
            pos = s.end
        out.append(text[pos:])
        return RedactionResult("".join(out), mapping, counts)


def rehydrate(text: str, mapping: dict[str, str]) -> str:
    """Swap [[TOKEN]] back to the original value. Unknown tokens are left alone."""
    return TOKEN_RE.sub(lambda m: mapping.get(m.group(1), m.group(0)), text)
