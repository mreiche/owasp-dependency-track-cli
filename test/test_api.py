from pathlib import Path
from time import sleep

import httpx
import owasp_dt
import pytest
from is_empty import empty
from owasp_dt.api.bom import upload_bom
from owasp_dt.api.config_property import update_config_property
from owasp_dt.api.event import is_token_being_processed_1
from owasp_dt.api.license_ import get_license
from owasp_dt.api.metrics import get_project_current_metrics
from owasp_dt.api.metrics import get_vulnerability_metrics
from owasp_dt.api.policy import create_policy, delete_policy
from owasp_dt.api.policy_condition import create_policy_condition
from owasp_dt.api.project import get_projects
from owasp_dt.api.violation import get_violations_by_project
from owasp_dt.api.vulnerability import get_all_vulnerabilities
from owasp_dt.models import UploadBomBody, IsTokenBeingProcessedResponse, ConfigProperty, ConfigPropertyPropertyType, Policy, PolicyViolationState, PolicyCondition, PolicyConditionSubject, PolicyConditionOperator, License
from owasp_dt.types import UNSET

from common import load_env
from owasp_dt_cli.analyze import retry
from owasp_dt_cli.api import create_client_from_env, get_findings_by_project_uuid

__base_dir = Path(__file__).parent
__upload_token: str | None = None
__project_uuid: str | None = None
__mit_license_uuid: str | None = None
__policy_uuid: str | None = None


def setup_module():
    load_env()


def teardown_module():
    if not empty(__policy_uuid):
        client = create_client_from_env()
        resp = delete_policy.sync_detailed(client=client, uuid=__policy_uuid)
        assert resp.status_code in [204, 404]


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
    global __project_uuid
    resp = get_projects.sync_detailed(client=client, name="test-project")
    projects = resp.parsed
    assert len(projects) > 0
    assert projects[0].uuid is not None
    __project_uuid = projects[0].uuid


@pytest.mark.depends(on=[
    'test_search_project_by_name',
    'test_get_scan_status',
    'test_get_vulnerabilities',
])
def test_get_project_findings(client: owasp_dt.Client):
    findings = get_findings_by_project_uuid(client=client, uuid=__project_uuid)
    assert len(findings) > 0
    for finding in findings:
        assert finding["component"]["name"]


@pytest.mark.depends(on=['test_search_project_by_name', 'test_get_scan_status'])
def test_get_project_metrics(client: owasp_dt.Client):
    resp = get_project_current_metrics.sync_detailed(client=client, uuid=__project_uuid)
    metrics = resp.parsed


@pytest.mark.depends(on=['test_search_project_by_name', 'test_get_scan_status'])
def test_get_project_violations(client: owasp_dt.Client):
    resp = get_violations_by_project.sync_detailed(client=client, uuid=__project_uuid)
    violations = resp.parsed


@pytest.mark.xfail(reason="Metrics data not available for unknown reason")
def test_get_vulnerability_metrics(client: owasp_dt.Client):
    resp = get_vulnerability_metrics.sync_detailed(client=client)
    vulnerabilities = resp.parsed
    assert len(vulnerabilities) > 0


@pytest.mark.depends(on=['test_trigger_vulnerabilities_update'])
def test_get_vulnerabilities(client: owasp_dt.Client):
    def _get_vulnerabilities():
        resp = get_all_vulnerabilities.sync_detailed(client=client, page_size=1)
        vulnerabilities = resp.parsed
        assert len(vulnerabilities) > 0

    retry(_get_vulnerabilities, 600)


def test_trigger_vulnerabilities_update(client: owasp_dt.Client):
    config = ConfigProperty(
        group_name="task-scheduler",
        property_name="nist.mirror.cadence",
        property_value="1",
        property_type=ConfigPropertyPropertyType.NUMBER,
    )
    resp = update_config_property.sync_detailed(client=client, body=config)
    assert resp.status_code == 200


def test_get_mit_license_uuid(client: owasp_dt.Client):
    global __mit_license_uuid
    if empty(__mit_license_uuid):
        resp = get_license.sync_detailed(client=client, license_id="MIT")
        assert resp.status_code == 200
        license = resp.parsed
        assert isinstance(license, License)
        __mit_license_uuid = str(license.uuid)
    return __mit_license_uuid


def test_create_test_policy(client: owasp_dt.Client):
    global __policy_uuid

    policy = Policy(
        uuid="",
        name="Forbid MIT license",
        violation_state=PolicyViolationState.FAIL,
    )
    resp = create_policy.sync_detailed(client=client, body=policy)
    assert resp.status_code == 201
    policy = resp.parsed
    assert isinstance(policy, Policy)
    __policy_uuid = str(policy.uuid)

    license_uuid = test_get_mit_license_uuid(client)

    condition = PolicyCondition(
        uuid="",
        policy=UNSET,
        subject=PolicyConditionSubject.LICENSE,
        operator=PolicyConditionOperator.IS,
        value=license_uuid,
    )
    resp = create_policy_condition.sync_detailed(client=client, uuid=policy.uuid, body=condition)
    assert resp.status_code == 201


def test_proxy_fails(monkeypatch, client: owasp_dt.Client):
    monkeypatch.setenv("HTTP_PROXY", "http://localhost:3128")
    with pytest.raises(expected_exception=httpx.ConnectError):
        test_trigger_vulnerabilities_update(client)
