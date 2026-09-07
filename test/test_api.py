import httpx
import owasp_dt
import pytest
from is_empty import empty
from owasp_dt.api.license_ import get_license
from owasp_dt.api.policy import create_policy
from owasp_dt.api.policy_condition import create_policy_condition
from owasp_dt.api.vulnerability import get_all_vulnerabilities
from owasp_dt.models import Policy, PolicyViolationState, PolicyCondition, PolicyConditionSubject, \
    PolicyConditionOperator, PolicyOperator, LicenseResponse
from owasp_dt.types import UNSET
from owasp_dt_v2.api.vuln_data_sources import trigger_vuln_data_source_mirror_run

from owasp_dt_cli import common

__mit_license_uuid: str | None = None


def assert_mit_license_uuid(client: owasp_dt.Client):
    global __mit_license_uuid
    if empty(__mit_license_uuid):
        resp = get_license.sync_detailed(client=client, license_id="MIT")
        assert resp.status_code == 200
        license = resp.parsed
        assert isinstance(license, LicenseResponse)
        __mit_license_uuid = str(license.uuid)
    return __mit_license_uuid


def test_create_test_policy(client: owasp_dt.Client):
    policy = Policy(
        uuid="",
        name="Forbid MIT license",
        violation_state=PolicyViolationState.FAIL,
        operator=PolicyOperator.ANY,
    )
    resp = create_policy.sync_detailed(client=client, body=policy)
    if resp.status_code == 409:
        return
    assert resp.status_code == 201
    policy = resp.parsed
    assert isinstance(policy, Policy)

    license_uuid = assert_mit_license_uuid(client)

    assert not empty(license_uuid), "MIT license not found"

    condition = PolicyCondition(
        uuid="",
        policy=UNSET,
        subject=PolicyConditionSubject.LICENSE,
        operator=PolicyConditionOperator.IS,
        value=license_uuid,
    )
    resp = create_policy_condition.sync_detailed(client=client, uuid=policy.uuid, body=condition)
    assert resp.status_code == 201

def test_trigger_mirror_nvd(client_v2: owasp_dt.Client):
    resp = trigger_vuln_data_source_mirror_run.sync_detailed(client=client_v2, name="nvd")
    assert resp.status_code in [202, 409]


def _get_vulnerabilities(client: owasp_dt.Client):
    resp = get_all_vulnerabilities.sync_detailed(client=client, page_size=1)
    vulnerabilities = resp.parsed
    assert len(vulnerabilities) > 0


@pytest.mark.depends(on=['test_trigger_mirror_nvd'])
def test_get_vulnerabilities(client: owasp_dt.Client):
    common.retry(lambda: _get_vulnerabilities(client), 1)


def test_proxy_fails(monkeypatch, client: owasp_dt.Client):
    monkeypatch.setenv("HTTP_PROXY", "http://localhost:3128")
    with pytest.raises(expected_exception=httpx.ConnectError):
        _get_vulnerabilities(client)
