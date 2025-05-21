from tabulate import tabulate
from colorama import Fore, Back, Style, init

from lib.api import Finding

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


def color_severity(severity: str):
    normalized = severity.upper()
    if normalized in __severity_color_map:
        color = __severity_color_map[normalized]
    else:
        color = Fore.LIGHTRED_EX

    return color + severity + Style.RESET_ALL

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
            f'{finding["component"]["group"]}.{finding["component"]["name"]}',
            f'{finding["component"]["version"]} ({finding["component"]["latestVersion"]})',
            f'{finding["vulnerability"]["vulnId"]} ({shorten(finding["vulnerability"]["description"])})',
            color_severity(finding["vulnerability"]["severity"]),
        ])
    print(tabulate(data, headers=headers, tablefmt="grid"))
