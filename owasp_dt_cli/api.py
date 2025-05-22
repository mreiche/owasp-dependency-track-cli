import json
from typing import TypedDict

from owasp_dt import Client
from owasp_dt.api.finding import get_findings_by_project
from owasp_dt.api.project import get_projects
from owasp_dt.models import Component, Vulnerability, Project
from tinystream import Stream, Opt

from owasp_dt_cli.config import reqenv, parse_true, getenv


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

# Wrappers for https://github.com/openapi-generators/openapi-python-client/issues/1256
class Finding(TypedDict, total=False):
    component: Component
    vulnerability: Vulnerability

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

def compare_last_bom_import(a: Project, b: Project):
    return b.last_bom_import - a.last_bom_import
