from typing import Generator, Callable, TypeVar

from owasp_dt import Client
from owasp_dt.api.project import get_projects
from owasp_dt.models import Project
from owasp_dt.types import Response
from tinystream import Stream

from owasp_dt_cli.config import reqenv, parse_true, getenv
from owasp_dt_cli.models import compare_last_bom_import


def create_client_from_env() -> Client:
    base_url = reqenv("OWASP_DTRACK_URL")
    return Client(
        base_url=f"{base_url}/api",
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

def find_project_by_name(client: Client, name: str, version: str = None, latest: bool = None) -> Project|None:
    def _loader(page_number: int):
        return get_projects.sync_detailed(
            client=client,
            name=name,
            page_number=page_number,
            page_size=1000
        )

    def _filter_version(project: Project):
        return project.version == version

    def _filter_latest(project: Project):
        return project.is_latest == latest

    for projects in page_result(_loader):
        stream = Stream(projects)
        if version:
            stream = stream.filter(_filter_version)

        if latest:
            stream = stream.filter(_filter_latest)

        opt_project = stream.sort(compare_last_bom_import).next()
        if opt_project.present:
            return opt_project.get()

    return None

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
