import json
from datetime import datetime
from typing import Generator, Callable, TypeVar

from owasp_dt import Client
from owasp_dt.api.finding import get_findings_by_project
from owasp_dt.api.project import get_projects
from owasp_dt.api.violation import get_violations
from owasp_dt.models import Project, PolicyViolation, Finding
from owasp_dt.types import Response
from tinystream import Stream, Opt

from owasp_dt_cli.config import reqenv, parse_true, getenv
from owasp_dt_cli.models import compare_last_bom_import, format_day


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
    def _loader(page_number: int):
        return get_projects.sync_detailed(
            client=client,
            name=name,
            page_number=page_number,
            page_size=1000
        )

    all_projects = []
    for projects in page_result(_loader):
        all_projects.extend(projects)

    stream = Stream(projects)
    if version:
        def _filter_version(project: Project):
            return project.version == version
        stream = stream.filter(_filter_version)

    if latest:
        def _filter_latest(project: Project):
            return project.is_latest == latest
        stream = stream.filter(_filter_latest)

    opt = stream.sort(compare_last_bom_import).next()
    return opt

T = TypeVar('T')

def page_result(cb: Callable[[int], Response[list[T]]]) -> Generator[list[T]]:
    page_number = 0
    while True:
        page_number += 1
        resp = cb(page_number)
        assert resp.status_code == 200
        items = resp.parsed
        if len(items) == 0:
            break
        else:
            yield items
