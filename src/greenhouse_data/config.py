"""Explicit optional client tuning; endpoint and credentials never have defaults."""
from dataclasses import dataclass
import math


@dataclass(frozen=True)
class ClientSettings:
    timeout_seconds: float = 30.0
    refresh_margin_seconds: float = 15.0

    def __post_init__(self) -> None:
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive and finite")
        if not math.isfinite(self.refresh_margin_seconds) or self.refresh_margin_seconds < 0:
            raise ValueError("refresh_margin_seconds must be nonnegative and finite")
