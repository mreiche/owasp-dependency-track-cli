from colorama import Fore, Style, init
from tabulate import tabulate

from owasp_dt_cli.api import Finding

init(autoreset=True)

__severity_color_map: dict[str, str] = {
    "MEDIUM": Fore.YELLOW,
    "HIGH": Fore.RED,
    "LOW": Fore.CYAN,
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

def format_version(finding: Finding):
    version = finding["component"]["version"]
    if "latestVersion" in finding["component"]:
        version += f" ({finding["component"]["latestVersion"]})"
    return version

def format_component(finding: Finding):
    component = finding["component"]["name"]
    if "group" in finding["component"]:
        component = f"{finding["component"]["group"]}.{component}"
    return component

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
            f'{(format_component(finding))}',
            f'{format_version(finding)}',
            f'{finding["vulnerability"]["vulnId"]} ({shorten(finding["vulnerability"]["description"])})',
            format_severity(finding["vulnerability"]["severity"]),
        ])
    print(tabulate(data, headers=headers, tablefmt="grid"))
