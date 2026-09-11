import logging
import os


def get_log_level(log_level_str: str):
    log_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(log_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    return log_level

__log_level = get_log_level(os.getenv("LOG_LEVEL", "INFO"))
logging.basicConfig(level=__log_level)

HTTPX_LOGGER = logging.getLogger("httpx")
if __log_level != logging.DEBUG:
    HTTPX_LOGGER.setLevel(os.getenv("HTTPX_LOG_LEVEL", "WARNING").upper())
else:
    HTTPX_LOGGER.setLevel(__log_level)

LOGGER = logging.getLogger("owasp-dtrack-cli")
