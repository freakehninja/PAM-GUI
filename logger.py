"""logger.py — Rotating audit logger."""

import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler

LOG_DIR  = Path("logs")
LOG_FILE = LOG_DIR / "rotation_audit.log"

def _setup():
    LOG_DIR.mkdir(exist_ok=True)
    lg = logging.getLogger("PAMAudit")
    if lg.handlers:
        return lg
    lg.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    fh  = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
    fh.setFormatter(fmt)
    ch  = logging.StreamHandler()
    ch.setFormatter(fmt)
    lg.addHandler(fh)
    lg.addHandler(ch)
    return lg

_lg = _setup()

class AuditLogger:
    def log(self, msg, level="INFO"):
        {"ERROR": _lg.error, "WARNING": _lg.warning}.get(level.upper(), _lg.info)(msg)
