from datetime import datetime
from math import floor
from time import sleep

from is_empty import empty
from owasp_dt.api.event import is_token_being_processed_1
from owasp_dt.api.project import get_projects
from owasp_dt.models import IsTokenBeingProcessedResponse, Project
from tinystream import Stream

from owasp_dt_cli import api, config
from owasp_dt_cli.log import LOGGER
from owasp_dt_cli.models import compare_last_bom_import
from owasp_dt_cli.output import print_findings_table
from owasp_dt_cli.upload import handle_upload


def handle_test(args):
    upload, client = handle_upload(args)

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
        stream = Stream(projects)
        if args.project_version:
            def _filter_version(project: Project):
                return project.version == args.project_version
            stream = stream.filter(_filter_version)

        if args.latest:
            def _filter_latest(project: Project):
                return project.is_latest == args.latest
            stream = stream.filter(_filter_latest)

        opt = stream.sort(compare_last_bom_import).next()
        assert opt.present, "Previous scanned project not found"

        project = opt.get()
        args.project_uuid = project.uuid

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
