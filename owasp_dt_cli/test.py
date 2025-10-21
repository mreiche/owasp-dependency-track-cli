from owasp_dt_cli.analyze import report_project, assert_project_uuid, wait_for_analyzation, handle_thresholds
from owasp_dt_cli.upload import handle_upload


def handle_test(args):
    upload, client = handle_upload(args)
    wait_for_analyzation(client=client, token=upload.token)
    assert_project_uuid(client=client, args=args)

    findings, violations = report_project(client=client, uuid=args.project_uuid)
    handle_thresholds(findings, violations)
