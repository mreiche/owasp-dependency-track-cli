import pytest
from owasp_dt import Client
from owasp_dt_v2.models import CreateSecretRequest, UpdateExtensionConfigRequest, UpdateExtensionConfigRequestConfig
from owasp_dt_v2.api.secrets import create_secret
from owasp_dt_v2.api.extensions import update_extension_config

def test_create_trivy_secret(client_v2: Client):
    trivy_secret = CreateSecretRequest(name="trivy-secret", value="secret")
    resp = create_secret.sync_detailed(client=client_v2, body=trivy_secret)
    assert resp.status_code in [201, 409]


@pytest.mark.depends(on=["test_create_trivy_secret"])
def test_configure_trivy_scanner(client_v2: Client):
    trivy_config = {
        "apiToken": "trivy-secret",
        "apiUrl": "http://trivy:8080",
        "enabled": True,
        "scanLibrary": True,
        "scanOs": True
    }
    config = UpdateExtensionConfigRequest(config=UpdateExtensionConfigRequestConfig.from_dict(trivy_config))
    resp = update_extension_config.sync_detailed(
        client=client_v2,
        extension_point_name="vuln-analyzer",
        extension_name="trivy",
        body=config
    )
    assert resp.status_code in [204, 304]
