import json
from pathlib import Path
from uuid import UUID

from owasp_dt.api.project import create_project
from owasp_dt.api.project import patch_project
from is_empty import empty, not_empty
from owasp_dt.models import Project
from tinystream import Opt

from owasp_dt_cli.api import create_client_from_env

def project_from_dict(project_data: dict):
    project_data["uuid"] = '12345678123456781234567812345678'
    project_data["lastBomImport"] = 0
    project = Project.from_dict(project_data)
    project.uuid = ""
    project.last_bom_import = 0
    #del project["uuid"]
    #del project.last_bom_import
    return project

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

    if not empty(args.project_name):
        project_data["name"] = args.project_name

    if not empty(args.project_version):
        project_data["version"] = args.project_version

    if not empty(args.latest):
        project_data["is_latest"] = args.latest

    client = create_client_from_env()
    project_uuid = Opt(project_data).kmap("uuid").if_absent(args.project_uuid).filter(not_empty)
    project = project_from_dict(project_data)
    project_dict = project.to_dict()
    print(project_dict)
    #project_data["uuid"] = '12345678123456781234567812345678'
    #project_data["lastBomImport"] = 0
    #project = Project.from_dict(project_data)
    #project.uuid = None
    #project.last_bom_import = None
    #print(project)
    #project = Project(**project_data)
    #print(project)
    #print(project_uuid.present)
    if project_uuid.present:
        resp = patch_project.sync_detailed(client=client, uuid=project_uuid.get(), body=project)
    else:
        resp = create_project.sync_detailed(client=client, body=project)
        print(resp.content)

    #print(project_data)
    pass
