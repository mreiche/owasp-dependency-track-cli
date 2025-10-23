from owasp_dt_cli.analyze import report_project, wait_for_token_processed, handle_thresholds
from owasp_dt_cli.upload import handle_upload
from owasp_dt_cli import common


def handle_test(args):
    upload, client = handle_upload(args)
    wait_for_token_processed(client=client, token=upload.token)
    common.assert_project_uuid(client=client, args=args)

    findings, violations = report_project(client=client, uuid=args.project_uuid)
    handle_thresholds(findings, violations)
