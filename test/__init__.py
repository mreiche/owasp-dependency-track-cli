from pathlib import Path

from dotenv import load_dotenv
from owasp_dt.api.policy import delete_policy, get_policies

from owasp_dt_cli.api import create_client_from_env

cwd = Path(__file__)

def setup_module():
    assert load_dotenv(cwd.parent / "test.env")

def teardown_module():
    client = create_client_from_env()
    resp = get_policies.sync_detailed(client=client)
    assert resp.status_code == 200

    policies = resp.parsed
    for policy in policies:
        if policy.name == "Forbid MIT license":
            resp = delete_policy.sync_detailed(client=client, uuid=policy.uuid)
            #assert resp.status_code == 204
