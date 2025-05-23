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
        if severity_count[severity] >= severity_threshold[severity] >= 0:
            raise ValueError(f"SEVERITY_THRESHOLD_{severity} hit: {severity_count[severity]}")

    violation_count: dict[str, int] = {}
    violation_threshold: dict[str, int] = {}
    for violation in violations:
        state = violation.policy_condition.policy.violation_state.name.upper()
        if state not in violation_count:
            violation_count[state] = 0
            violation_threshold[state] = int(config.getenv(f"VIOLATION_THRESHOLD_{state}", "-1"))

        violation_count[state] += 1
        if violation_count[state] >= violation_threshold[state] >= 0:
            raise ValueError(f"VIOLATION_THRESHOLD_{state} hit: {violation_count[state]}")
