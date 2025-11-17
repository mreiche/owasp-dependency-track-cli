import random
from pathlib import Path

import pytest
from owasp_dt import Client
from owasp_dt.api.project import get_projects

from owasp_dt_cli import api

__base_dir = Path(__file__).parent

__name_version = f"v{random.randrange(0, 99999)}"
__uuid_version = f"v{random.randrange(0, 99999)}"
__project_name = "test-upload"
__project_uuid: None


@pytest.mark.parametrize("version", [__name_version])
def test_upload_by_name(version: str, parser):
    args = parser.parse_args([
        "upload",
        "--project-name",
        __project_name,
        "--auto-create",
        "--project-version",
        version,
        str(__base_dir / "files/test.sbom.xml"),
    ])
    args.func(args)


@pytest.mark.depends(on=['test_upload_by_name'])
@pytest.mark.parametrize("version", [__name_version])
def test_analyze_by_name(version: str, parser):
    args = parser.parse_args([
        "analyze",
        "--project-name",
        __project_name,
        "--project-version",
        version,
    ])
    args.func(args)


@pytest.mark.depends(on=['test_analyze_by_name'])
@pytest.mark.parametrize("version", [__name_version])
def test_report_by_name(version: str, parser, capsys):
    args = parser.parse_args([
        "report",
        "--project-name",
        __project_name,
        "--project-version",
        version,
    ])
    args.func(args)

    captured = capsys.readouterr()
    print(captured.out)

@pytest.mark.depends(on=['test_upload_by_name'])
@pytest.mark.parametrize("version", [__uuid_version])
def test_upload_by_uuid(version: str, client: Client, parser):
    global __project_uuid
    project = api.find_project_by_name(name=__project_name, client=client)
    assert project
    __project_uuid = str(project.uuid)
    assert isinstance(__project_uuid, str)

    args = parser.parse_args([
        "upload",
        "--project-uuid",
        __project_uuid,
        "--project-version",
        version,
        str(__base_dir / "files/test.sbom.xml"),
    ])

    args.func(args)


@pytest.mark.depends(on=['test_upload_by_uuid'])
@pytest.mark.parametrize("version", [__uuid_version])
def test_analyze_by_uuid(version: str, parser):
    args = parser.parse_args([
        "analyze",
        "--project-uuid",
        __project_uuid,
        "--project-version",
        version,
    ])
    args.func(args)


@pytest.mark.depends(on=['test_analyze_by_uuid'])
@pytest.mark.parametrize("version", [__uuid_version])
def test_cleanup_older(version: str, client: Client):
    def _loader(page_number: int):
        return get_projects.sync_detailed(
            client=client,
            name="test-upload",
            page_number=page_number,
            page_size=1000
        )

    projects_loaded = 0
    for projects in api.page_result(_loader):
        for project in projects:
            projects_loaded += 1
            assert project.active is False if project.version != version else True

    assert projects_loaded > 0
