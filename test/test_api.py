from pathlib import Path

import pytest

import owasp_dt
from common import load_env
from lib.api import create_client_from_env
from owasp_dt.api.bom import upload_bom
from owasp_dt.api.project import get_projects
from owasp_dt.models import UploadBomBody

__base_dir = Path(__file__).parent

def setup_module():
    load_env()

__upload_token = None

@pytest.fixture
def client():
    yield create_client_from_env()

def test_upload_sbom(client: owasp_dt.Client):
    global __upload_token
    with open(__base_dir / "test.sbom.json") as sbom_file:
        resp = upload_bom.sync(client=client, body=UploadBomBody(
            project_name="test-project",
            auto_create=True,
            bom=sbom_file.read()
        ))
        assert resp is not None, "API call failed. Check client permissions."
        assert resp.token is not None
        __upload_token = resp.token

@pytest.mark.depends(on=['test_upload_sbom'])
def test_get_scan_status(client: owasp_dt.Client):
    pass

@pytest.mark.depends(on=['test_upload_sbom'])
def test_get_projects(client: owasp_dt.Client):
    projects = get_projects.sync(client=client)
    assert len(projects) > 0
