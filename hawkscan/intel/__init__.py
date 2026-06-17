"""Threat-intelligence data: API-to-capability and MITRE ATT&CK mapping."""

from .capabilities import (
    CATEGORY_SEVERITY,
    categorize,
    Capability,
)

__all__ = ["CATEGORY_SEVERITY", "categorize", "Capability"]
