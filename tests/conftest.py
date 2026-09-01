"""Pytest configuration.

The tests directory itself goes on `sys.path` so suites can import `support`,
which holds fixtures-free helpers shared between them.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
