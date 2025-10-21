import math
import time
from datetime import timedelta
from time import sleep
from typing import Callable

from owasp_dt_cli import log


def retry(callable: Callable, seconds: float, wait_time: float = 2):
    retries = math.ceil(seconds / wait_time)
    #start_date = datetime.now()
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
        raise exception
        #raise Exception(f"{exception} after {datetime.now()-start_date}")

    return ret

def schedule(sleep_time: timedelta, task: Callable):
    task_duration = 0
    while True:
        try:
            tic = time.time()
            task()
            task_duration = time.time() - tic
        except Exception as e:
            log.LOGGER.exception(e)
        finally:
            sleep_seconds = sleep_time.total_seconds() - task_duration
            time.sleep(max(sleep_seconds, 0))
