import math
from datetime import datetime
from time import sleep
from typing import Callable

from is_empty import empty
from owasp_dt import Client
from owasp_dt.api.event import is_token_being_processed_1
from owasp_dt.api.finding import analyze_project
from owasp_dt.api.violation import get_violations_by_project
from owasp_dt.api.vulnerability import get_all_vulnerabilities
from owasp_dt.models import IsTokenBeingProcessedResponse, PolicyViolation

from owasp_dt_cli import api, config, report
from owasp_dt_cli.api import create_client_from_env, Finding
from owasp_dt_cli.log import LOGGER
from owasp_dt_cli.upload import assert_project_identity


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

def wait_for_analyzation(client: Client, token: str) -> IsTokenBeingProcessedResponse:
    def _read_processed_():
        LOGGER.info(f"Waiting for token '{token}' being processed...")
        resp = is_token_being_processed_1.sync_detailed(client=client, uuid=token)
        status = resp.parsed
        assert isinstance(status, IsTokenBeingProcessedResponse)

    return retry(_read_processed_, int(config.getenv("ANALYZE_TIMEOUT_SEC", "300")))

def report_project(client: Client, uuid: str) -> tuple[list[Finding], list[PolicyViolation]]:
    resp = get_all_vulnerabilities.sync_detailed(client=client, page_size=1)
    vulnerabilities = resp.parsed
    assert len(vulnerabilities) > 0, "No vulnerabilities in database"

    findings = api.get_findings_by_project_uuid(client=client, uuid=uuid)
    report.print_findings_table(findings)

    resp = get_violations_by_project.sync_detailed(client=client, uuid=uuid)
    violations = resp.parsed
    report.print_violations_table(violations)
    return findings, violations

def assert_project_uuid(client: Client, args):
    def _find_project():
        opt = api.find_project_by_name(
            client=client,
            name=args.project_name,
            version=args.project_version,
            latest=args.latest
        )
        assert opt.present, f"Project not found: {args.project_name}:{args.project_version}" + (f" (latest)" if args.latest else "")
        return opt.get()

    if empty(args.project_uuid):
        project = retry(_find_project, 20)
        args.project_uuid = project.uuid


def handle_analyze(args, client: Client = None):
    assert_project_identity(args)

    if not client:
        client = create_client_from_env()

    assert_project_uuid(client=client, args=args)
    resp = analyze_project.sync_detailed(client=client, uuid=args.project_uuid)
    wait_for_analyzation(client=client, token=resp.parsed.token)
    report_project(client=client, uuid=args.project_uuid)
