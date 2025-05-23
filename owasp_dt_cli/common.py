import math
import time
from datetime import datetime, timedelta
from time import sleep
from typing import Callable

from owasp_dt import Client
from owasp_dt.api.event import is_token_being_processed_1
from owasp_dt.models import IsTokenBeingProcessedResponse

from owasp_dt_cli import config
from owasp_dt_cli.log import LOGGER


def retry(callable: Callable, seconds: float, wait_time: float = 2):
    retries = math.ceil(seconds / wait_time)
    start_date = datetime.now()
    exception = None
    ret = None
    for i in range(retries):
        try:
            exception = None
            ret = callable()
            break
        except Exception as e:
            exception = e
        sleep(wait_time)

    if exception:
        raise Exception(f"{exception} after {datetime.now()-start_date}")

    return ret

def schedule(sleep_time: timedelta, task: Callable):
    task_duration = 0
    while True:
        try:
            tic = time.time()
            task()
            task_duration = time.time() - tic
        except Exception as e:
            LOGGER.exception(e)
        finally:
            sleep_seconds = sleep_time.total_seconds() - task_duration
            time.sleep(max(sleep_seconds, 0))

def wait_for_analyzation(client: Client, token: str) -> IsTokenBeingProcessedResponse:
    def _read_process_status():
        LOGGER.info(f"Waiting for token '{token}' being processed...")
        resp = is_token_being_processed_1.sync_detailed(client=client, uuid=token)
        status = resp.parsed
        assert isinstance(status, IsTokenBeingProcessedResponse)

    return retry(_read_process_status, int(config.getenv("ANALYZE_TIMEOUT_SEC", "300")))
