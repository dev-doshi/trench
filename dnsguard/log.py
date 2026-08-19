"""Logging setup: human or JSON structured logs."""
from __future__ import annotations

import json
import logging
import sys
import time


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "ts": round(record.created, 3),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        for k, v in getattr(record, "extra_fields", {}).items():
            obj[k] = v
        return json.dumps(obj, default=str)


class _HumanFormatter(logging.Formatter):
    COLORS = {"DEBUG": "\033[2m", "INFO": "\033[36m", "WARNING": "\033[33m", "ERROR": "\033[31m"}
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        t = time.strftime("%H:%M:%S", time.localtime(record.created))
        color = self.COLORS.get(record.levelname, "")
        return f"{color}{t} {record.levelname[:4]:<4}{self.RESET} {record.name}: {record.getMessage()}"


def setup(level: str = "info", json_logs: bool = False) -> None:
    root = logging.getLogger("dnsguard")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(_JsonFormatter() if json_logs else _HumanFormatter())
    root.addHandler(h)
    root.propagate = False


def get(name: str) -> logging.Logger:
    return logging.getLogger(f"dnsguard.{name}")
