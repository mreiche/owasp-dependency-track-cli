import json
from typing import TypedDict, Generator

from owasp_dt import Client
from owasp_dt.api.finding import get_findings_by_project
from owasp_dt.api.project import get_projects
from owasp_dt.models import Component, Vulnerability, Project, PolicyViolation, Finding
from tinystream import Stream, Opt

from owasp_dt_cli.config import reqenv, parse_true, getenv
from owasp_dt_cli.models import compare_last_bom_import, format_day
from owasp_dt.api.violation import get_violations
from datetime import datetime

def create_client_from_env() -> Client:
    return Client(
        base_url=reqenv("OWASP_DTRACK_URL"),
        headers={
            "X-Api-Key": reqenv("OWASP_DTRACK_API_KEY")
        },
        verify_ssl=getenv("OWASP_DTRACK_VERIFY_SSL", "1", parse_true),
        raise_on_unexpected_status=False,
        httpx_args={
            "proxy": getenv("HTTPS_PROXY", lambda: getenv("HTTP_PROXY", None)),
            #"no_proxy": getenv("NO_PROXY", "")
        }
    )

# Wrapper for https://github.com/openapi-generators/openapi-python-client/issues/1256
def get_findings_by_project_uuid(client: Client, uuid: str) -> list[Finding]:
    resp = get_findings_by_project.sync_detailed(client=client, uuid=uuid)
    assert resp.status_code != 401
    return json.loads(resp.content)

def find_project_by_name(client: Client, name: str, version: str = None, latest: bool = None) -> Opt[Project]:
    resp = get_projects.sync_detailed(client=client, name=name, page_size=10)
    projects = resp.parsed
    stream = Stream(projects)
    if version:
        def _filter_version(project: Project):
            return project.version == version
        stream = stream.filter(_filter_version)

    if latest is not None:
        def _filter_latest(project: Project):
            return project.is_latest == latest
        stream = stream.filter(_filter_latest)

    opt = stream.sort(compare_last_bom_import).next()
    return opt

def get_all_violations(client: Client, since: datetime) -> Generator[list[PolicyViolation]]:
    page_number = 0
    while True:
        page_number += 1
        resp = get_violations.sync_detailed(
            client=client,
            show_inactive=False,
            page_number=page_number,
            page_size=1000,
            occurred_on_date_from=format_day(since),
        )
        assert resp.status_code == 200
        violations = resp.parsed
        if len(violations) == 0:
            break
        else:
            yield resp.parsed
