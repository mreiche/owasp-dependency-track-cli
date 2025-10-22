import logging
import os

def get_log_level(log_level_str: str):
    log_level = getattr(logging, log_level_str, None)
    assert isinstance(log_level, int), 'Invalid log level: %s' % log_level
    return log_level

logging.basicConfig(level=get_log_level(os.getenv("LOG_LEVEL", "INFO")))
logging.getLogger("httpx").setLevel(os.getenv("HTTPX_LOG_LEVEL", "WARNING"))
LOGGER = logging.getLogger("owasp-dtrack-cli")
