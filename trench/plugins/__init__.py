"""Plugin system: hook into the resolve pipeline (on_query / on_answer)."""
from .api import Plugin
from .loader import PluginManager

__all__ = ["Plugin", "PluginManager"]
