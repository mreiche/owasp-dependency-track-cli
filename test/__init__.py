from pathlib import Path

from dotenv import load_dotenv
from owasp_dt.api.policy import delete_policy, get_policies
from owasp_dt import utils

base_dir = Path(__file__).parent

test_project_name = "test-api"

def setup_module():
    assert load_dotenv(base_dir / "test.env")

def teardown_module():
    client = utils.create_client_from_env()
    resp = get_policies.sync_detailed(client=client)
    assert resp.status_code == 200

    policies = resp.parsed
    for policy in policies:
        if policy.name == "Forbid MIT license":
            resp = delete_policy.sync_detailed(client=client, uuid=policy.uuid)
            #assert resp.status_code == 204
