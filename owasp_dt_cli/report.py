from colorama import Fore, Style, init
from owasp_dt import Client
from owasp_dt.api.finding import get_findings_by_project
from owasp_dt.api.violation import get_violations_by_project
from owasp_dt.api.vulnerability import get_all_vulnerabilities
from owasp_dt.models import Component, FindingComponent, FindingVulnerability
from owasp_dt.models import Finding
from owasp_dt.models import PolicyViolation
from tabulate import tabulate
from tinystream import Stream

from owasp_dt_cli import api, config, common, models

init(autoreset=True)

__severity_color_map: dict[str, str] = {
    "MEDIUM": Fore.YELLOW,
    "HIGH": Fore.RED,
    "LOW": Fore.CYAN,
}

__state_color_map: dict[str, str] = {
    "WARN": Fore.YELLOW,
    "FAIL": Fore.RED,
    "INFO": Fore.CYAN,
}


def shorten(text: str, max_length: int = 100):
    if len(text) > max_length:
        return text[:97] + "..."
    else:
        return text


def format_severity(severity: str):
    normalized = severity.upper()
    if normalized in __severity_color_map:
        color = __severity_color_map[normalized]
    else:
        color = Fore.LIGHTRED_EX

    return color + severity + Style.RESET_ALL


def format_violation_state(state: str):
    normalized = state.upper()
    if normalized in __state_color_map:
        color = __state_color_map[normalized]
    else:
        color = Fore.LIGHTRED_EX

    return color + state + Style.RESET_ALL


def format_component_version(component: FindingComponent | Component):
    version = component.version
    if isinstance(component, FindingComponent):
        version += f" ({component.latest_version if component.latest_version else "?"})"

    return version


def format_component_identifier(component: FindingComponent | Component):
    name = component.name
    if component.group:
        name = f"{component.group}.{name}"

    return name


def format_scoring(vulnerability: FindingVulnerability):
    scores = []
    scores.append(str(vulnerability.cvss_v3_base_score) if vulnerability.cvss_v3_base_score else "?")
    scores.append(str(vulnerability.cvss_v2_base_score) if vulnerability.cvss_v2_base_score else "?")
    return f"{format_severity(vulnerability.severity)} ({', '.join(scores)})"


def print_findings_table(findings: list[Finding]):
    headers = [
        "Component",
        "Version (latest)",
        "Vulnerability",
        "Severity (CVSS3, CVSS2)"
    ]
    data = []
    for finding in findings:
        data.append([
            format_component_identifier(finding.component),
            format_component_version(finding.component),
            f'{finding.vulnerability.vuln_id} ({shorten(finding.vulnerability.description)})',
            format_scoring(finding.vulnerability),
        ])
    if len(data) > 0:
        print("FINDINGS")
        print(tabulate(data, headers=headers, tablefmt="grid"))
    else:
        print("NO FINDINGS")


def print_violations_table(violations: list[PolicyViolation]):
    headers = [
        "Component",
        "Version (latest)",
        "Policy",
        "State"
    ]
    data = []
    for violation in violations:
        data.append([
            format_component_identifier(violation.component),
            format_component_version(violation.component),
            violation.policy_condition.policy.name,
            format_violation_state(violation.policy_condition.policy.violation_state.name),
        ])
    if len(data) > 0:
        print("POLICY VIOLATIONS")
        print(tabulate(data, headers=headers, tablefmt="grid"))
    else:
        print("NO POLICY VIOLATIONS")


def report_project(client: Client, uuid: str) -> tuple[list[Finding], list[PolicyViolation]]:
    resp = get_all_vulnerabilities.sync_detailed(client=client, page_size=1)
    vulnerabilities = resp.parsed
    assert len(vulnerabilities) > 0, "No vulnerabilities in database"

    resp = get_findings_by_project.sync_detailed(client=client, uuid=uuid)
    assert resp.status_code != 401
    findings = Stream(resp.parsed).sort(models.compare_finding_score).collect()
    print_findings_table(findings)

    resp = get_violations_by_project.sync_detailed(client=client, uuid=uuid)
    violations = resp.parsed
    print_violations_table(violations)
    return findings, violations


def handle_report(args):
    common.assert_project_identity(args)
    client = api.create_client_from_env()
    common.assert_project_uuid(client=client, args=args)

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
