from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..schema import Flow


@dataclass
class Detection:
    """A scored finding before fusion. Not yet an alert."""
    threat_class: str
    src_ip: str
    dst_ip: str | None
    score: float                       # 0..1, raw detector output
    evidence: dict[str, Any]
    ts_event: float
    flow_ids: list[str] = field(default_factory=list)
    observed_flows: int = 1
    reverse_direction_visible: bool = True
    caveat: str | None = None


class Detector:
    """Base class. Stateful, streaming, and structurally unable to send."""
    name = "base"
    model_version = "0.1.0"
    threat_class = "benign"
    threshold = 0.5

    def observe(self, flow: Flow) -> None:      # accumulate window state
        raise NotImplementedError

    def evaluate(self, window_end: float) -> list[Detection]:
        raise NotImplementedError

    def reset_window(self) -> None:
        raise NotImplementedError
