from owasp_dt import Client
from owasp_dt.api.event import is_token_being_processed_1
from owasp_dt.api.finding import analyze_project
from owasp_dt.models import BomUploadResponse, IsTokenBeingProcessedResponse

from owasp_dt_cli import api, common, config, log
from owasp_dt_cli.report import handle_thresholds, report_project


def handle_analyze(args):
    common.validate_project_identity(args)
    client = api.create_client_from_env()
    common.validate_project_uuid(client=client, args=args)

    resp = analyze_project.sync_detailed(client=client, uuid=args.project_uuid)
    common.validate(resp.status_code in [200, 202], f"Project analyzation status unknown: {resp.parsed} (status code: {resp.status_code})")

    bom_upload = resp.parsed
    common.validate(isinstance(bom_upload, BomUploadResponse), f"Unexpected response: {bom_upload}")

    wait_for_token_processed(client=client, token=bom_upload.token)
    findings, violations = report_project(client=client, uuid=args.project_uuid)
    handle_thresholds(findings, violations)


def wait_for_token_processed(client: Client, token: str) -> IsTokenBeingProcessedResponse:
    def _read_process_status():
        log.LOGGER.info(f"Waiting for token '{token}' being processed...")
        resp = is_token_being_processed_1.sync_detailed(client=client, uuid=token)
        status = resp.parsed
        common.validate(isinstance(status, IsTokenBeingProcessedResponse), str(resp))
        common.validate(status.processing is False, str(status))

    return common.retry(_read_process_status, int(config.getenv("ANALYZE_TIMEOUT_SEC", "300")))
