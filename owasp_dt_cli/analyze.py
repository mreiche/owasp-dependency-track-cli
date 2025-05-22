from datetime import datetime
from math import floor
from time import sleep

from is_empty import empty
from owasp_dt import Client
from owasp_dt.api.event import is_token_being_processed_1
from owasp_dt.api.finding import analyze_project
from owasp_dt.api.violation import get_violations_by_project
from owasp_dt.models import IsTokenBeingProcessedResponse, PolicyViolation

from owasp_dt_cli import api, config, report
from owasp_dt_cli.api import create_client_from_env, Finding
from owasp_dt_cli.log import LOGGER
from owasp_dt_cli.upload import assert_project_identity


def wait_for_analyzation(client: Client, token: str) -> IsTokenBeingProcessedResponse:
    wait_time = 2
    test_timeout_sec = int(config.getenv("TEST_TIMEOUT_SEC", "300"))
    retries = floor(test_timeout_sec / wait_time)
    status = None
    start_date = datetime.now()
    for i in range(retries):
        LOGGER.info(f"Waiting for token '{token}' being processed...")
        resp = is_token_being_processed_1.sync_detailed(client=client, uuid=token)
        status = resp.parsed
        assert isinstance(status, IsTokenBeingProcessedResponse)
        if not status.processing:
            break
        sleep(wait_time)

    assert status and status.processing is False, f"Upload has not been processed within {datetime.now()-start_date}"
    return status

def report_project(client: Client, uuid: str) -> tuple[list[Finding], list[PolicyViolation]]:
    findings = api.get_findings_by_project_uuid(client=client, uuid=uuid)
    if len(findings):
        report.print_findings_table(findings)

    resp = get_violations_by_project.sync_detailed(client=client, uuid=uuid)
    violations = resp.parsed
    if len(violations):
        report.print_violations_table(violations)

    return findings, violations

def assert_project_uuid(client: Client, args):
    if empty(args.project_uuid):
        opt = api.find_project_by_name(
            client=client,
            name=args.project_name,
            version=args.project_version,
            latest=args.latest
        )
        assert opt.present, "Project not found"
        args.project_uuid = opt.get().uuid

def handle_analyze(args, client: Client = None):

    assert_project_identity(args)

    if not client:
        client = create_client_from_env()

    assert_project_uuid(client=client, args=args)
    resp = analyze_project.sync_detailed(client=client, uuid=args.project_uuid)
    wait_for_analyzation(client=client, token=resp.parsed.token)
    report_project(client=client, uuid=args.project_uuid)
