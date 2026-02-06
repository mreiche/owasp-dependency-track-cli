import logging
import os


def get_log_level(log_level_str: str):
    log_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(log_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    return log_level

logging.basicConfig(level=get_log_level(os.getenv("LOG_LEVEL", "INFO")))
logging.getLogger("httpx").setLevel(os.getenv("HTTPX_LOG_LEVEL", "WARNING").upper())
LOGGER = logging.getLogger("owasp-dtrack-cli")
