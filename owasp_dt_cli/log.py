import logging
import os


numeric_level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % numeric_level)

logging.basicConfig(level=numeric_level)
LOGGER = logging.getLogger("owasp-dtrack-cli")
