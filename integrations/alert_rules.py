"""Configurable alert filtering rules for security notifications."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


SEVERITY_LEVELS = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass
class AlertRules:
    """Thresholds and filters for deciding which findings trigger alerts."""

    min_risk_score: int = 7
    allowed_severities: set[str] = field(
        default_factory=lambda: {"Critical", "High"}
    )
    quiet_hours_start: int = 23  # 23:00 local
    quiet_hours_end: int = 7  # 07:00 local
    quiet_hours_block_non_critical: bool = True

    def should_alert(
        self, finding: dict, now: Optional[datetime] = None
    ) -> bool:
        """Return True if this finding crosses the alert threshold."""
        risk = finding.get("risk_score", 0)
        severity = finding.get("severity", "Low")

        # Risk score gate
        if risk < self.min_risk_score:
            return False

        # Severity gate (if configured)
        if self.allowed_severities and severity not in self.allowed_severities:
            return False

        # Quiet hours
        if self.quiet_hours_block_non_critical and now is None:
            now = datetime.now()
        if now and self.quiet_hours_block_non_critical and severity != "Critical":
            hour = now.hour
            if self.quiet_hours_start > self.quiet_hours_end:
                # wraps midnight (e.g. 23-7)
                if hour >= self.quiet_hours_start or hour < self.quiet_hours_end:
                    return False
            else:
                if self.quiet_hours_start <= hour < self.quiet_hours_end:
                    return False

        return True

    @classmethod
    def from_dict(cls, cfg: dict) -> "AlertRules":
        return cls(
            min_risk_score=cfg.get("min_risk_score", 7),
            allowed_severities=set(cfg.get("allowed_severities", ["Critical", "High"])),
            quiet_hours_start=cfg.get("quiet_hours_start", 23),
            quiet_hours_end=cfg.get("quiet_hours_end", 7),
            quiet_hours_block_non_critical=cfg.get("quiet_hours_block_non_critical", True),
        )

    @classmethod
    def from_json_file(cls, path: str) -> "AlertRules":
        """Load rules from a JSON config file."""
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))
