from datetime import datetime, timedelta

import owasp_dt
import prometheus_client as prometheus
from owasp_dt.api.finding import get_all_findings_1
from owasp_dt.api.violation import get_violations
from owasp_dt.models import PolicyViolation, Finding

from owasp_dt_cli import api
from owasp_dt_cli.common import schedule
from owasp_dt_cli.log import LOGGER
from owasp_dt_cli.models import format_day, day_format
from owasp_dt_cli.prometheus import PrometheusAdapter


def handle_prometheus_metrics(args):
    adapter = PrometheusAdapter()
    registry = prometheus.REGISTRY
    adapter.disable_python_metrics(registry)

    cvss_score = prometheus.Gauge(adapter.prefix_metric_key("cvss_score"), "Project CVEs and their scoring", ["project_name", "component_name", "cve", "cvss_version", "severity"], registry=registry)
    violations = prometheus.Gauge(adapter.prefix_metric_key("policy_violations"), "Project Policy violations", ["project_name", "component_name", "policy_name", "state"], registry=registry)
    client = api.create_client_from_env()
    since = datetime.strptime(args.initial_start_date, day_format)
    active_project_names = []

    def _update_metrics():
        nonlocal since, active_project_names
        current_project_names: dict[str, bool] = {}
        current_project_names.update(update_finding_metrics(client, cvss_score, since))
        current_project_names.update(update_violation_metrics(client, violations, since))

        # Always using today
        since = datetime.now()

        # Cleanup Prometheus stats for
        for project_name in active_project_names:
            if project_name not in current_project_names:
                for instrument in (cvss_score, violations):
                    adapter.remove_by_label(instrument, {"project_name": project_name})

        active_project_names = current_project_names.keys()


    if args.serve:
        prometheus.start_http_server(args.serve_port, addr="0.0.0.0")
        LOGGER.info(f"Started server at http://localhost:{args.serve_port}")
        scrape_interval = timedelta(seconds=args.scrape_interval)
        LOGGER.info(f"Scrape interval is {scrape_interval}")
        schedule(sleep_time=scrape_interval, task=_update_metrics)
    else:
        _update_metrics()
        print(prometheus.generate_latest(registry))


def update_finding_metrics(
        client: owasp_dt.Client,
        instrument: prometheus.Gauge,
        since: datetime,
) -> dict[str, bool]:
    current_active_projects: dict[str, bool] = {}

    def _add_findings(findings:list[Finding]):
        for finding in findings:
            vulnerability = finding.vulnerability
            component = finding.component
            current_active_projects[component["projectName"]] = True

            if "cvssV2BaseScore" in vulnerability and vulnerability["cvssV2BaseScore"] >= 0:
                instrument.labels(*[
                    component["projectName"],
                    component["name"],
                    vulnerability["vulnId"],
                    "v2",
                    vulnerability["severity"],
                ]).set(vulnerability["cvssV2BaseScore"])

            if "cvssV3BaseScore" in vulnerability and vulnerability["cvssV3BaseScore"] >= 0:
                instrument.labels(*[
                    component["projectName"],
                    component["name"],
                    vulnerability["vulnId"],
                    "v3",
                    vulnerability["severity"],
                ]).set(vulnerability["cvssV3BaseScore"])
    try:
        resp = get_all_findings_1.sync_detailed(
            client=client,
            show_inactive=False,
            show_suppressed=False,
            attributed_on_date_from=format_day(since),
        )
        assert resp.status_code == 200
        _add_findings(resp.parsed)
    except Exception as e:
        LOGGER.error(e)

    return current_active_projects

def update_violation_metrics(
        client: owasp_dt.Client,
        instrument: prometheus.Gauge,
        since: datetime,
) -> dict[str, bool]:
    current_active_projects: dict[str, bool] = {}
    def _add_violations(violations: list[PolicyViolation]):
        for violation in violations:
            component = violation.component
            project = violation.project
            policy = violation.policy_condition.policy
            instrument.labels(*[
                project.name,
                component.name,
                policy.name,
                policy.violation_state.name,
            ]).set(1)

    try:
        def _loader(page_number: int):
            return get_violations.sync_detailed(
                client=client,
                show_inactive=False,
                page_number=page_number,
                page_size=1000,
                occurred_on_date_from=format_day(since),
            )
        for violations in api.page_result(_loader):
            _add_violations(violations)
    except Exception as e:
        LOGGER.error(e)

    return list(current_active_projects.keys())
