from datetime import timedelta

import owasp_dt
import prometheus_client as prometheus
from owasp_dt.api.finding import get_all_findings_1
from owasp_dt.api.violation import get_violations
from owasp_dt.api.project import create_project, get_projects, patch_project, delete_projects, get_project
from owasp_dt.models import PolicyViolation, Finding, Project

from owasp_dt_cli import api
from owasp_dt_cli.common import schedule
from owasp_dt_cli.log import LOGGER
from owasp_dt_cli.prometheus import PrometheusAdapter


def handle_prometheus_metrics(args):
    adapter = PrometheusAdapter()
    registry = prometheus.REGISTRY
    adapter.disable_python_metrics(registry)

    cvss_score = prometheus.Gauge(adapter.prefix_metric_key("cvss_score"), "Project CVEs and their scoring", ["project_name", "group_name", "component_name", "cve", "cvss_version", "severity"], registry=registry)
    violations = prometheus.Gauge(adapter.prefix_metric_key("policy_violations"), "Project Policy violations", ["project_name", "group_name", "component_name", "policy_name", "state"], registry=registry)
    client = api.create_client_from_env()
    active_project_names = []

    def _update_metrics():
        nonlocal active_project_names
        current_project_names: dict[str, bool] = {}
        current_project_names.update(update_finding_metrics(client, cvss_score))
        current_project_names.update(update_violation_metrics(client, violations))

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
) -> dict[str, bool]:
    current_active_projects: dict[str, bool] = {}
    project_cache: dict[str, Project] = {}

    def _add_findings(findings: list[Finding]):
        for finding in findings:
            vulnerability = finding.vulnerability
            component = finding.component
            current_active_projects[component.project_name] = True

            project_uuid = str(component.project)
            if project_uuid not in project_cache:
                resp = get_project.sync_detailed(client=client, uuid=project_uuid)
                assert resp.status_code in [200]
                project_cache[project_uuid] = resp.parsed

            project = project_cache[project_uuid]

            def _add_score(version: str, cvss: float):
                instrument.labels(*[
                    component.project_name,
                    project.group,
                    component.name,
                    vulnerability.vuln_id,
                    version,
                    vulnerability.severity,
                ]).set(cvss)

            if vulnerability.cvss_v3_base_score and vulnerability.cvss_v3_base_score > 0:
                _add_score("v3", vulnerability.cvss_v3_base_score)
            elif vulnerability.cvss_v2_base_score and vulnerability.cvss_v2_base_score > 0:
                _add_score("v2", vulnerability.cvss_v2_base_score)
            else:
                _add_score("v3", 0.1)

    try:
        resp = get_all_findings_1.sync_detailed(
            client=client,
            show_inactive=False,
            show_suppressed=False,
        )
        assert resp.status_code == 200
        findings = resp.parsed
        _add_findings(findings)
    except Exception as e:
        LOGGER.error(e)

    return current_active_projects


def update_violation_metrics(
        client: owasp_dt.Client,
        instrument: prometheus.Gauge,
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
            )

        for violations in api.page_result(_loader):
            _add_violations(violations)
    except Exception as e:
        LOGGER.error(e)

    return list(current_active_projects.keys())
