from owasp_dt_cli import config
from owasp_dt_cli.analyze import wait_for_analyzation, report_project, assert_project_uuid
from owasp_dt_cli.upload import handle_upload


def handle_test(args):
    upload, client = handle_upload(args)
    wait_for_analyzation(client=client, token=upload.token)
    assert_project_uuid(client=client, args=args)

    findings, violations = report_project(client=client, uuid=args.project_uuid)
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
