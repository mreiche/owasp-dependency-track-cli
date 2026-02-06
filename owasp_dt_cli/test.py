from owasp_dt_cli import common
from owasp_dt_cli.analyze import (
    handle_thresholds,
    report_project,
    wait_for_token_processed,
)
from owasp_dt_cli.upload import handle_upload


def handle_test(args):
    upload, client = handle_upload(args)
    wait_for_token_processed(client=client, token=upload.token)
    common.validate_project_uuid(client=client, args=args)

    findings, violations = report_project(client=client, uuid=args.project_uuid)
    handle_thresholds(findings, violations)
