import random
from pathlib import Path

import owasp_dt
import pytest
from owasp_dt.api.project import get_projects
from owasp_dt.models import Project
from tinystream import Stream

from owasp_dt_cli import api

__base_dir = Path(__file__).parent

__project_name = "keep-active"


@pytest.mark.parametrize("version", ["deactivate", "keep-active"])
def test_upload(version: str, parser):
    args = parser.parse_args([
        "upload",
        "--project-name",
        __project_name,
        "--auto-create",
        "--project-version",
        version,
        "--deactivate-others",
        "false",
        str(__base_dir / "files/test.sbom.xml"),
    ])
    args.func(args)

@pytest.mark.depends(on=['test_upload'])
@pytest.mark.parametrize("version", ["keep-active"])
def test_activate_project(version: str, parser):
    args = parser.parse_args([
        "project",
        "activate",
        "--project-name",
        __project_name,
        "--project-version",
        version
    ])
    args.func(args)

@pytest.mark.depends(on=['test_activate_project'])
@pytest.mark.parametrize("version", ["latest"])
def test_upload_latest(version: str, parser):
    args = parser.parse_args([
        "upload",
        "--project-name",
        __project_name,
        "--auto-create",
        "--project-version",
        version,
        "--latest",
        str(__base_dir / "files/test.sbom.xml"),
    ])
    args.func(args)

@pytest.mark.depends(on=['test_upload_latest'])
def test_active_projects(client: owasp_dt.Client):
    resp = get_projects.sync_detailed(
        client=client,
        name=__project_name,
        page_number=1,
        page_size=1000
    )

    def _filter_active(project: Project):
        return project.active

    projects = resp.parsed
    active_projects = Stream(projects).filter(_filter_active).count()
    assert active_projects == 2
