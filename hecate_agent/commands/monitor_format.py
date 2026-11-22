"""Format for the live monitor."""

from __future__ import annotations

from typing import Optional

from rich.text import Text


def _bar(value: Optional[float], width: int = 22) -> Text:
    if value is None:
        return Text("[ telemetry unavailable ]", style="dim")
    value = max(0.0, min(100.0, value))
    full = round(width * value / 100)
    color = "bright_magenta" if value >= 85 else "bright_cyan"
    return Text("█" * full + "░" * (width - full) + f" {value:5.1f}%", style=color)
