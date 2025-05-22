from pathlib import Path

import httpx
import pytest

from common import load_env
from owasp_dt_cli import api
from owasp_dt_cli.args import create_parser

__base_dir = Path(__file__).parent

def setup_module():
    load_env()

def test_test():
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

@pytest.mark.depends(on=['test_test'])
def test_uploaded():
    client = api.create_client_from_env()
    opt = api.find_project_by_name(client=client, name="test-project")
    project = opt.get()
    assert project.version == "latest"
    assert project.is_latest == True

def test_proxy_fails(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://localhost:3128")
    with pytest.raises(expected_exception=httpx.ConnectError):
        test_test()
