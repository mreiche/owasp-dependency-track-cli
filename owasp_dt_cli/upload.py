from pathlib import Path

from is_empty import empty
from owasp_dt import Client
from owasp_dt.api.bom import upload_bom
from owasp_dt.models import UploadBomBody, BomUploadResponse

from owasp_dt_cli import api

def assert_project_identity(args):
    assert not empty(args.project_uuid) or not empty(args.project_name), "At least a project UUID or a project name is required"

def handle_upload(args) -> tuple[BomUploadResponse, Client]:
    sbom_file: Path = args.sbom
    assert sbom_file.exists(), f"{sbom_file} doesn't exists"

    assert_project_identity(args)

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
    assert resp.status_code != 404, f"Project not found: {args.project_name}:{args.project_version}"

    upload = resp.parsed
    assert isinstance(upload, BomUploadResponse), upload

    return upload, client
