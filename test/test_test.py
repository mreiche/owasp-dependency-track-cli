from pathlib import Path
from time import sleep

import pytest

import owasp_dt
from common import load_env
from lib.api import create_client_from_env, get_findings_by_project_uuid
from owasp_dt.api.bom import upload_bom
from owasp_dt.api.project import get_projects
from owasp_dt.models import UploadBomBody, IsTokenBeingProcessedResponse
from owasp_dt.api.event import is_token_being_processed_1
from owasp_dt.api.finding import get_findings_by_project

__base_dir = Path(__file__).parent

def setup_module():
    load_env()

__upload_token = None
__project_id = None

@pytest.fixture
def client():
    yield create_client_from_env()

def test_rendering_with_custom_template():
    output_dir = __base_dir / "out2"
    clear_dir(output_dir)

    test_env = os.environ.copy()
    test_env["OUTPUT_DIR"] = str(output_dir)
    test_env["TEMPLATE_FILE"] = str(__base_dir / "templates/other-template.j2.md")
    ret = subprocess.run(
        ["python", __base_dir / "../gen.py", __base_dir / "test-pipeline.yml"],
        capture_output=True,
        text=True,
        env=test_env
    )
    assert ret.returncode == 0
    assert ret.stderr == "INFO:gen.py:1 files generated\n", ret.stderr

    with open(output_dir / "test-pipeline.md", "r") as file:
        file_content = file.read()
        assert "This is a special template for testing custom templates" in file_content
        assert "## Workflow" in file_content
