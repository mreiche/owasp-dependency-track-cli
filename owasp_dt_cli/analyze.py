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
    findings, violations = report_project(client=client, uuid=args.project_uuid)
    handle_thresholds(findings, violations)


def handle_thresholds(findings: list[Finding], violations: list[PolicyViolation]):
    severity_count: dict[str, int] = {}
    severity_threshold: dict[str, int] = {}
    cvss_v3_total = 0
    cvss_v3_threshold = int(config.getenv("CVSS_V3_THRESHOLD", "-1"))
    cvss_v2_total = 0
    cvss_v2_threshold = int(config.getenv("CVSS_V2_THRESHOLD", "-1"))

    for finding in findings:
        vulnerability = finding.vulnerability
        severity = vulnerability.severity.upper()
        if severity not in severity_count:
            severity_count[severity] = 0
            severity_threshold[severity] = int(config.getenv(f"SEVERITY_THRESHOLD_{severity}", "-1"))

        severity_count[severity] += 1
        if severity_count[severity] >= severity_threshold[severity] >= 0:
            raise ValueError(f"SEVERITY_THRESHOLD_{severity} hit: {severity_count[severity]}")

        if vulnerability.cvss_v3_base_score:
            cvss_v3_total += vulnerability.cvss_v3_base_score
            if cvss_v3_total >= cvss_v3_threshold >= 0:
                raise ValueError(f"CVSS_V3_THRESHOLD hit: {cvss_v3_total}")

        if vulnerability.cvss_v2_base_score:
            cvss_v2_total += vulnerability.cvss_v2_base_score
            if cvss_v2_total >= cvss_v2_threshold >= 0:
                raise ValueError(f"CVSS_V2_THRESHOLD hit: {cvss_v2_total}")

    violation_count: dict[str, int] = {}
    violation_threshold: dict[str, int] = {}
    for violation in violations:
        state = violation.policy_condition.policy.violation_state.name.upper()
        if state not in violation_count:
            violation_count[state] = 0
            violation_threshold[state] = int(config.getenv(f"VIOLATION_THRESHOLD_{state}", "-1"))

        violation_count[state] += 1
        if violation_count[state] >= violation_threshold[state] >= 0:
            raise ValueError(f"VIOLATION_THRESHOLD_{state} hit: {violation_count[state]}")


def wait_for_analyzation(client: Client, token: str) -> IsTokenBeingProcessedResponse:
    def _read_process_status():
        log.LOGGER.info(f"Waiting for token '{token}' being processed...")
        resp = is_token_being_processed_1.sync_detailed(client=client, uuid=token)
        status = resp.parsed
        assert isinstance(status, IsTokenBeingProcessedResponse)
        assert status.processing is False

    return common.retry(_read_process_status, int(config.getenv("ANALYZE_TIMEOUT_SEC", "300")))
