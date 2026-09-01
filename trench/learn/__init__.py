"""Query-pattern learning.

Deliberately narrow: the only thing Trench "learns" is which names this
network actually uses (an exponentially-weighted popularity score that survives
restarts), and the only thing that knowledge drives is proactive cache prewarm.
Security thresholds (DGA/tunnel) are NOT auto-tuned from traffic — a detector
that recalibrates itself on unlabeled data can be trained into false negatives.
"""
from __future__ import annotations

from .popularity import PopularityTracker, prewarm

__all__ = ["PopularityTracker", "prewarm"]
