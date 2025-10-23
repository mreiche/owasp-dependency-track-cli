from pathlib import Path

import owasp_dt
from is_empty import empty
from owasp_dt import Client
from owasp_dt.api.bom import upload_bom
from owasp_dt.api.project import get_projects, patch_project, get_project
from owasp_dt.models import UploadBomBody, BomUploadResponse, Project, ProjectProperty
from tinystream import Stream, Opt

from owasp_dt_cli import api, common, log, models


def handle_upload(args) -> tuple[BomUploadResponse, Client]:
    sbom_file: Path = args.sbom
    assert sbom_file.exists(), f"{sbom_file} doesn't exists"

    common.assert_project_identity(args)

    client = api.create_client_from_env()
    body = UploadBomBody(
        is_latest=args.latest,
        auto_create=args.auto_create,
        bom=sbom_file.read_text()
    )
    if args.project_uuid:
        body.project = args.project_uuid

    if args.project_name:
        body.project_name = args.project_name

    if args.parent_uuid:
        body.parent_uuid = args.parent_uuid

    if args.parent_name:
        body.parent_name = args.parent_name

    if args.project_version:
        body.project_version = args.project_version

    resp = upload_bom.sync_detailed(client=client, body=body)
    assert resp.status_code != 404, f"Project not found: {args.project_name}:{args.project_version} (you may missing --auto-create)"

    upload = resp.parsed
    assert isinstance(upload, BomUploadResponse), upload

    if args.deactivate_others:
        deactivate_other_projects(client=client, args=args)

    return upload, client


def deactivate_other_projects(client: owasp_dt.Client, args):
    if empty(args.project_name):
        resp = get_project.sync_detailed(client=client, uuid=args.project_uuid)
        assert resp.status_code in [200]
        existing_project = resp.parsed
        args.project_name = existing_project.name

    def _filter_project_version(project: Project):
        return project.version != args.project_version and project.active

    def _filter_keep_active_property(project: Project):
        def _find_keep_active_property(property: ProjectProperty):
            return property.group_name == models.keep_active_property.group_name and property.property_name == models.keep_active_property.property_name

        opt_property = Opt(project).map_key("properties").stream().find(_find_keep_active_property)
        return opt_property.absent or opt_property.get().property_value.lower() != "true"

    def _loader(page_number: int):
        return get_projects.sync_detailed(
            client=client,
            name=args.project_name,
            page_number=page_number,
            page_size=1000
        )

    for projects in api.page_result(_loader):
        for project in Stream(projects).filter(_filter_project_version).filter(_filter_keep_active_property):
            resp = patch_project.sync_detailed(client=client, uuid=project.uuid, body=Project(active=False))
            if resp.status_code not in (200,):
                log.LOGGER.error(f"Unable to patch project '{project.uuid}'")
