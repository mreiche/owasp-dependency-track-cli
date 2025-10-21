from colorama import Fore, Style, init
from owasp_dt.models import PolicyViolation, Component, FindingComponent, Finding
from tabulate import tabulate

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

def format_component_version(component: FindingComponent|Component):
    version = component.version
    if isinstance(component, FindingComponent):
        if component.latest_version:
            version += f" ({component.latest_version})"

    return version

def format_component_identifier(component: FindingComponent|Component):
    name = component.name
    if component.group:
        name = f"{component.group}.{name}"

    return name

def print_findings_table(findings: list[Finding]):
    headers = [
        "Component",
        "Version (latest)",
        "Vulnerability",
        "Severity"
    ]
    data = []
    for finding in findings:
        data.append([
            format_component_identifier(finding.component),
            format_component_version(finding.component),
            f'{finding.vulnerability.vuln_id} ({shorten(finding.vulnerability.description)})',
            format_severity(finding.vulnerability.severity),
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
