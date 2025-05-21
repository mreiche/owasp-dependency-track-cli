from datetime import datetime
from math import floor
from pathlib import Path
from time import sleep

from is_empty import empty
from owasp_dt.api.bom import upload_bom
from owasp_dt.api.event import is_token_being_processed_1
from owasp_dt.api.project import get_projects
from owasp_dt.models import UploadBomBody, IsTokenBeingProcessedResponse, BomUploadResponse

from owasp_dt_cli import api, config
from owasp_dt_cli.log import LOGGER
from owasp_dt_cli.output import print_findings_table


def handle_test(args):
    sbom_file: Path = args.sbom
    assert sbom_file.exists(), f"{sbom_file} doesn't exists"

    assert not empty(args.project_uuid) or not empty(args.project_name), "At least a project UUID or a project name is required"

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

    resp = upload_bom.sync_detailed(client=client, body=body)
    assert resp.status_code != 404, "Project not found"

    upload = resp.parsed
    assert isinstance(upload, BomUploadResponse), upload

    wait_time = 2
    test_timeout_sec = int(config.getenv("TEST_TIMEOUT_SEC", "300"))
    retries = floor(test_timeout_sec / wait_time)
    status = None
    start_date = datetime.now()
    for i in range(retries):
        LOGGER.info(f"Waiting for token '{upload.token}' being processed...")
        resp = is_token_being_processed_1.sync_detailed(client=client, uuid=upload.token)
        status = resp.parsed
        assert isinstance(status, IsTokenBeingProcessedResponse)
        if not status.processing:
            break
        sleep(wait_time)

    assert status and status.processing is False, f"Upload has not been processed within {datetime.now()-start_date}"

    if empty(args.project_uuid):
        resp = get_projects.sync_detailed(client=client, name=args.project_name, page_size=10)
        projects = resp.parsed
        assert len(projects) == 1, f"Multiple projects found matching '{args.project_name}'"
        args.project_uuid = projects[0].uuid

    findings = api.get_findings_by_project_uuid(client=client, uuid=args.project_uuid)
    if len(findings):
        print_findings_table(findings)

        severity_count: dict[str, int] = {}
        severity_threshold: dict[str, int] = {}

        for finding in findings:
            severity = finding["vulnerability"]["severity"].upper()
            if severity not in severity_count:
                severity_count[severity] = 0
                severity_threshold[severity] = int(config.getenv(f"SEVERITY_THRESHOLD_{severity}", "-1"))

            severity_count[severity] += 1
            if 0 <= severity_threshold[severity] <= severity_count[severity]:
                raise ValueError(f"SEVERITY_THRESHOLD_{severity} hit: {severity_count[severity]}")
