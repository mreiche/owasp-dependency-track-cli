import json
from pathlib import Path

from is_empty import empty, not_empty
from owasp_dt.api.project import create_project, get_projects, patch_project, delete_projects
from owasp_dt.api.project_property import delete_property_1
from owasp_dt.models import Project, ProjectProperty, ProjectPropertyPropertyType
from owasp_dt.types import Unset
from tinystream import Opt, Stream

from owasp_dt_cli import api, common, log, models


def create_project_patches_from_project_data(project_data: dict) -> tuple[Project, list[ProjectProperty]]:
    if "properties" in project_data:
        properties: list[ProjectProperty] = Stream(project_data["properties"]).map(ProjectProperty.from_dict).collect()
        del project_data["properties"]
    else:
        properties = []

    return Project.from_dict(project_data), properties


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

    client = api.create_client_from_env()
    opt_uuid = Opt(project_data).kmap("uuid").if_absent(args.project_uuid).filter(not_empty)
    project_patch, properties = create_project_patches_from_project_data(project_data)

    if not empty(args.project_uuid):
        project_patch.uuid = args.project_uuid

    if not empty(args.project_name):
        project_patch.name = args.project_name

    if not empty(args.project_version):
        project_patch.version = args.project_version

    if args.latest:
        project_patch.is_latest = args.latest

    if opt_uuid.present:
        project_uuid = opt_uuid.get()
        resp = patch_project.sync_detailed(client=client, uuid=project_uuid, body=project_patch)
        assert resp.status_code in [304, 200, 201], resp.content
    else:
        assert not isinstance(project_patch.name, Unset) and not empty(project_patch.name), "At least a project name is required"
        resp = create_project.sync_detailed(client=client, body=project_patch)
        if resp.status_code == 409:
            existing_project = api.find_project_by_name(client=client, name=project_patch.name, version=project_patch.version, latest=project_patch.is_latest)
            assert isinstance(existing_project, Project), "The backend complains about project naming conflict, but the project does not exists, this should not happen"
            resp = patch_project.sync_detailed(client=client, uuid=existing_project.uuid, body=project_patch)
            assert resp.status_code in [304, 200, 201]
            project_uuid = existing_project.uuid
        else:
            assert resp.status_code == 201, resp.content
            created_project = resp.parsed
            project_uuid = created_project.uuid

    if len(properties) > 0:
        log.LOGGER.info("Update project properties")
        for property in properties:
            api.upsert_project_property(client=client, uuid=project_uuid, property=property)

    print(project_uuid)


def handle_project_activate(args):
    common.assert_project_identity(args)
    client = api.create_client_from_env()
    common.assert_project_uuid(client=client, args=args)

    project_patch = Project(active=True)
    resp = patch_project.sync_detailed(client=client, uuid=args.project_uuid, body=project_patch)
    assert resp.status_code in [304, 200, 201], resp.content
    api.upsert_project_property(client=client, uuid=args.project_uuid, property=models.keep_active_property)


def handle_project_deactivate(args):
    common.assert_project_identity(args)
    client = api.create_client_from_env()
    common.assert_project_uuid(client=client, args=args)

    project_patch = Project(active=False)
    resp = patch_project.sync_detailed(client=client, uuid=args.project_uuid, body=project_patch)
    assert resp.status_code in [304, 200, 201], resp.content
    delete_property_1.sync_detailed(client=client, uuid=args.project_uuid, body=models.keep_active_property)


def handle_project_property_remove(args):
    common.assert_project_identity(args)
    client = api.create_client_from_env()
    common.assert_project_uuid(client=client, args=args)
    property = ProjectProperty(
        group_name=args.group_name,
        property_name=args.property_name,
        property_type=ProjectPropertyPropertyType.STRING,
        property_value="",
    )
    delete_property_1.sync_detailed(client=client, uuid=args.project_uuid, body=property)


def handle_project_cleanup(args):
    client = api.create_client_from_env()

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
