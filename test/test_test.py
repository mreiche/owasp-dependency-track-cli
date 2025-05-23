from pathlib import Path

import pytest

from owasp_dt_cli import api
from owasp_dt_cli.args import create_parser

__base_dir = Path(__file__).parent

@pytest.mark.depends(on=["test/test_api.py::test_create_test_policy", "test/test_api.py::test_get_vulnerabilities"])
def test_test(capsys):
    parser = create_parser()
    args = parser.parse_args([
        "test",
        "--project-name",
        "test-project",
        "--auto-create",
        "--latest",
        "--project-version",
        "latest",
        str(__base_dir / "test.sbom.xml"),
    ])

    assert args.latest == True
    assert args.project_version == "latest"

    args.func(args)
    captured = capsys.readouterr()
    assert "CVE-2018-20225" in captured.out
    assert "Forbid MIT license" in captured.out

@pytest.mark.depends(on=['test_test'])
def test_uploaded():
    client = api.create_client_from_env()
    opt = api.find_project_by_name(client=client, name="test-project")
    project = opt.get()
    assert project.version == "latest"
    assert project.is_latest == True
