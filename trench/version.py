"""Single source of truth for the version string."""
from __future__ import annotations

# PEP 440. setuptools reads this attribute for the distribution version, so a
# non-conforming string here fails the build rather than the release.
__version__ = "2.0.0"
USER_AGENT = f"trench/{__version__}"
