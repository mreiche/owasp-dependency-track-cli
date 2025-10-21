import os

from is_empty import empty
from owasp_dt import Client
from owasp_dt.api.event import is_token_being_processed_1
from owasp_dt.api.finding import analyze_project, get_findings_by_project
from owasp_dt.api.violation import get_violations_by_project
from owasp_dt.api.vulnerability import get_all_vulnerabilities
from owasp_dt.models import IsTokenBeingProcessedResponse, Finding
from owasp_dt.models import PolicyViolation, BomUploadResponse

from owasp_dt_cli import api, report, config, log, common
from owasp_dt_cli.upload import assert_project_identity


def report_project(client: Client, uuid: str) -> tuple[list[Finding], list[PolicyViolation]]:
    resp = get_all_vulnerabilities.sync_detailed(client=client, page_size=1)
    vulnerabilities = resp.parsed
    assert len(vulnerabilities) > 0, "No vulnerabilities in database"

    resp = get_findings_by_project.sync_detailed(client=client, uuid=uuid)
    assert resp.status_code != 401
    findings = resp.parsed
    report.print_findings_table(findings)

    resp = get_violations_by_project.sync_detailed(client=client, uuid=uuid)
    violations = resp.parsed
    report.print_violations_table(violations)
    return findings, violations


def assert_project_uuid(client: Client, args):
    def _find_project():
        project = api.find_project_by_name(
            client=client,
            name=args.project_name,
            version=args.project_version,
            latest=args.latest
        )
        assert project is not None, f"Project not found: {args.project_name}:{args.project_version}" + (f" (latest)" if args.latest else "")
        return project

    if empty(args.project_uuid):
        project = common.retry(_find_project, int(os.getenv("PROJECT_TIMEOUT_SEC", "20")))
        args.project_uuid = project.uuid


def handle_analyze(args):
    assert_project_identity(args)

    client = api.create_client_from_env()

    assert_project_uuid(client=client, args=args)
    resp = analyze_project.sync_detailed(client=client, uuid=args.project_uuid)
    assert resp.status_code in [200, 202], f"Project analyzation status unknown: {resp.parsed} (status code: {resp.status_code})"

    bom_upload = resp.parsed
    assert isinstance(bom_upload, BomUploadResponse), f"Unexpected response: {bom_upload}"

    wait_for_analyzation(client=client, token=bom_upload.token)
    report_project(client=client, uuid=args.project_uuid)


def wait_for_analyzation(client: Client, token: str) -> IsTokenBeingProcessedResponse:
    def _read_process_status():
        log.LOGGER.info(f"Waiting for token '{token}' being processed...")
        resp = is_token_being_processed_1.sync_detailed(client=client, uuid=token)
        status = resp.parsed
        assert isinstance(status, IsTokenBeingProcessedResponse)
        assert status.processing is False

    return common.retry(_read_process_status, int(config.getenv("ANALYZE_TIMEOUT_SEC", "300")))
