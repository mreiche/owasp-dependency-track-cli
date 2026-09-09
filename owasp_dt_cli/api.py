from typing import TypeVar

from owasp_dt import Client, utils
from owasp_dt.api.project import get_projects
from owasp_dt.models import Project
from tinystream import Stream

from owasp_dt_cli import models

T = TypeVar("T")

def find_project_by_name(
    client: Client, name: str,
    version: str | None = None,
    latest: bool | None = None,
) -> Project|None:
    def _loader(page_number: int):
        return get_projects.sync_detailed(
            client=client,
            name=name,
            exclude_inactive=False,
            page_number=page_number,
            page_size=1000,
        )

    def _filter_version(project: Project):
        return project.version == version

    def _filter_latest(project: Project):
        return project.is_latest == latest

    for projects in utils.page_result(_loader):
        stream = Stream(projects)
        if version:
            stream = stream.filter(_filter_version)
        elif latest:
            stream = stream.filter(_filter_latest)

        opt_project = stream.sort(models.compare_last_bom_import).next()
        if opt_project.present:
            return opt_project.get()

    return None
