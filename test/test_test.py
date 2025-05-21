from pathlib import Path

import httpx
import pytest

from common import load_env
from owasp_dt_cli.api import create_client_from_env
from owasp_dt_cli.args import create_parser
from owasp_dt.api.project import get_projects

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
        "maus",
        str(__base_dir / "test.sbom.xml"),
    ])

    assert args.latest == True
    assert args.project_version == "maus"

    args.func(args)

@pytest.mark.depends(on=['test_test'])
#@pytest.mark.xfail(reason="Version doesn't get updated by OWASP DT")
def test_uploaded():
    client = create_client_from_env()
    resp = get_projects.sync_detailed(client=client, name="test-project")
    projects = resp.parsed
    assert projects[0].version == "maus"
    assert projects[0].is_latest == True

def test_proxy_fails(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://localhost:3128")
    with pytest.raises(expected_exception=httpx.ConnectError):
        test_test()
