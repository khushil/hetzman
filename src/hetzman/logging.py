import os
import sys
from datetime import datetime

from .config import LOG_FILE


def log_message(message: str, level: str = "INFO") -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [{level}] {message}\n"
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(entry)
    except OSError as e:
        sys.stderr.write(f"Warning: Could not write to log: {e}\n")
