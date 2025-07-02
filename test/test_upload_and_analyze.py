import random
from pathlib import Path

import pytest
from owasp_dt.api.project import get_projects

from owasp_dt_cli import api
from owasp_dt_cli.api import create_client_from_env

from owasp_dt_cli.args import create_parser

__base_dir = Path(__file__).parent

__versions = []
for _ in range(2):
    __versions.append(f"v{random.randrange(0, 99999)}")

@pytest.mark.parametrize("version", __versions)
def test_upload(version: str):
    parser = create_parser()
    args = parser.parse_args([
        "upload",
        "--project-name",
        "test-upload",
        "--auto-create",
        "--project-version",
        version,
        "--keep-previous",
        str(__base_dir / "files/test.sbom.xml"),
    ])

    args.func(args)

@pytest.mark.depends(on=['test_upload'])
@pytest.mark.parametrize("version", __versions)
def test_analyze(version: str):
    parser = create_parser()
    args = parser.parse_args([
        "analyze",
        "--project-name",
        "test-upload",
        "--project-version",
        version,
    ])
    args.func(args)

@pytest.mark.depends(on=['test_analyze'])
def test_upload_newest():
    parser = create_parser()
    args = parser.parse_args([
        "upload",
        "--auto-create",
        "--project-name",
        "test-upload",
        "--project-version",
        "newest",
        "--latest",
        str(__base_dir / "files/test.sbom.xml"),
    ])
    args.func(args)

    client = create_client_from_env()

    def _loader(page_number: int):
        return get_projects.sync_detailed(
            client=client,
            name="test-upload",
            page_number=page_number,
            page_size=1000
        )

    for projects in api.page_result(_loader):
        for project in projects:
            assert project.active is False if project.version != "newest" else True
