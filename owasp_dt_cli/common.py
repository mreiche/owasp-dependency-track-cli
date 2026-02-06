import math
import os
import time
from datetime import timedelta
from time import sleep
from typing import Callable

from is_empty import empty
from owasp_dt import Client

from owasp_dt_cli import api, log


def retry(callable: Callable, seconds: float, wait_time: float = 3):
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

def validate_project_uuid(client: Client, args):
    def _find_project():
        project = api.find_project_by_name(
            client=client,
            name=args.project_name,
            version=args.project_version,
            latest=args.latest,
        )
        validate(project is not None, f"Project not found: {args.project_name}:{args.project_version} {' [latest]' if args.latest else ''}")
        log.LOGGER.info(f"Found project {project.name}:{project.version} (UUID: {project.uuid}){' [latest]' if project.is_latest else ''}")
        return project

    if empty(args.project_uuid):
        project = retry(_find_project, int(os.getenv("PROJECT_TIMEOUT_SEC", "20")))
        args.project_uuid = project.uuid

def validate_project_identity(args):
    validate(not empty(args.project_uuid) or not empty(args.project_name), "At least a project UUID or a project name is required")

def validate(condition: bool, msg: str = None):
    if not condition:
        raise ValueError(msg)
