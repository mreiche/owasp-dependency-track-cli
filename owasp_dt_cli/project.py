import json
from pathlib import Path

from owasp_dt.api.project import create_project, get_projects, patch_project, delete_projects
from is_empty import empty, not_empty
from owasp_dt.models import Project
from owasp_dt.types import Unset
from tinystream import Opt

from owasp_dt_cli import api
from owasp_dt_cli.api import create_client_from_env

def handle_project_upsert(args):
    file_defined = not empty(args.file)
    string_defined = not empty(args.json)
    assert file_defined or string_defined, "At least a JSON file or string is required"

    if file_defined:
        project_file = Path(args.file)
        try:
            project_data = json.load(project_file.open())
        except Exception as e:
            raise Exception(f"Error loading JSON file '{args.file}': {e}")
    else:
        try:
            project_data = json.loads(args.json)
        except Exception as e:
            raise Exception(f"Error parsing JSON '{args.json}': {e}")

    client = create_client_from_env()
    opt_uuid = Opt(project_data).kmap("uuid").if_absent(args.project_uuid).filter(not_empty)
    project = Project.from_dict(project_data)

    if not empty(args.project_uuid):
        project.uuid = args.project_uuid

    if not empty(args.project_name):
        project.name = args.project_name

    if not empty(args.project_version):
        project.version = args.project_version

    if args.latest:
        project.is_latest = args.latest

    if opt_uuid.present:
        project_uuid = opt_uuid.get()
        resp = patch_project.sync_detailed(client=client, uuid=project_uuid, body=project)
        assert resp.status_code in [304, 200, 201]
        print(project_uuid)
    else:
        assert not isinstance(project.name, Unset) and not empty(project.name), "At least a project name is required"
        resp = create_project.sync_detailed(client=client, body=project)
        if resp.status_code == 409:
            existing_project = api.find_project_by_name(client=client, name=project.name, version=project.version, latest=project.is_latest)
            assert isinstance(existing_project, Project), "The backend complains about project naming conflict, but the project does not exists, this should not happen"
            resp = patch_project.sync_detailed(client=client, uuid=existing_project.uuid, body=project)
            assert resp.status_code in [304, 200, 201]
            print(existing_project.uuid)
        else:
            assert resp.status_code == 201, resp.content
            created_project = resp.parsed
            print(created_project.uuid)


def handle_project_cleanup(args):
    client = create_client_from_env()
    def _loader(page_number: int):
        return get_projects.sync_detailed(
            client=client,
            name=None if empty(args.project_name) else args.project_name,
            page_number=page_number,
            page_size=1000
        )
    project_uuids_to_delete = []
    for projects in api.page_result(_loader):
        for project in projects:
            if project.active is False:
                project_uuids_to_delete.append(project.uuid)

    if len(project_uuids_to_delete) > 0:
        delete_projects.sync_detailed(client=client, body=project_uuids_to_delete)
