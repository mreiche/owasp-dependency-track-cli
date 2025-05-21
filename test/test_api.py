from pathlib import Path
from time import sleep

import pytest

import owasp_dt
from common import load_env
from owasp_dt_cli.api import create_client_from_env, get_findings_by_project_uuid
from owasp_dt.api.bom import upload_bom
from owasp_dt.api.project import get_projects
from owasp_dt.models import UploadBomBody, IsTokenBeingProcessedResponse
from owasp_dt.api.event import is_token_being_processed_1

__base_dir = Path(__file__).parent

def setup_module():
    load_env()

__upload_token = None
__project_id = None

@pytest.fixture
def client():
    yield create_client_from_env()

def test_upload_sbom(client: owasp_dt.Client):
    global __upload_token
    with open(__base_dir / "test.sbom.xml") as sbom_file:
        resp = upload_bom.sync_detailed(client=client, body=UploadBomBody(
            project_name="test-project",
            auto_create=True,
            bom=sbom_file.read()
        ))
        upload = resp.parsed
        assert upload is not None, "API call failed. Check client permissions."
        assert upload.token is not None
        __upload_token = upload.token

@pytest.mark.depends(on=['test_upload_sbom'])
def test_get_scan_status(client: owasp_dt.Client):
    max_tries = 10
    i = 0
    for i in range(max_tries):
        resp = is_token_being_processed_1.sync_detailed(client=client, uuid=__upload_token)
        status = resp.parsed
        assert isinstance(status, IsTokenBeingProcessedResponse)
        if not status.processing:
            break
        sleep(1)

    assert i < max_tries, f"Scan not finished within {max_tries} seconds"


@pytest.mark.depends(on=['test_upload_sbom'])
def test_search_project_by_name(client: owasp_dt.Client):
    global __project_id
    resp = get_projects.sync_detailed(client=client, name="test-project")
    projects = resp.parsed
    assert len(projects) > 0
    assert projects[0].uuid is not None
    __project_id = projects[0].uuid

@pytest.mark.depends(on=['test_search_project_by_name','test_get_scan_status'])
def test_get_project_findings(client: owasp_dt.Client):
    findings = get_findings_by_project_uuid(client=client, uuid=__project_id)
    assert len(findings) > 0
