from pathlib import Path

from dotenv import load_dotenv
from owasp_dt.api.policy import delete_policy, get_policies
from owasp_dt.api.project import delete_project, get_projects, delete_projects
from tinystream import Stream

from owasp_dt_cli.api import create_client_from_env, find_project_by_name

cwd = Path(__file__)

test_project_name = "test-api"

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

    # resp = get_projects.sync_detailed(
    #     client=client,
    #     name=test_project_name,
    #     page_size=1000
    # )
    # projects = resp.parsed
    # resp = delete_projects.sync_detailed(client=client, body=Stream(projects).map_key("uuid").collect())
    # assert resp.status_code == 204
