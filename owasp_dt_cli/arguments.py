import argparse
import pathlib
from argparse import ArgumentParser

from owasp_dt_cli import models, config
from owasp_dt_cli.analyze import handle_analyze
from owasp_dt_cli.metrics import handle_prometheus_metrics
from owasp_dt_cli.project import handle_project_upsert, handle_project_cleanup, handle_project_property_remove, handle_project_activate, handle_project_deactivate
from owasp_dt_cli.report import handle_report
from owasp_dt_cli.test import handle_test
from owasp_dt_cli.upload import handle_upload


def add_sbom_file(parser: ArgumentParser, default="gatekeeper.json"):
    parser.add_argument("sbom", help="SBOM file path", type=pathlib.Path, default=default)

def add_upload_params(parser: ArgumentParser):
    add_project_params(parser)
    parser.add_argument("--auto-create", help="Requires permission: PROJECT_CREATION_UPLOAD", action='store_true', default=False)
    parser.add_argument("--parent-uuid", help="Parent project UUID", required=False)
    parser.add_argument("--parent-name", help="Parent project name", required=False)
    parser.add_argument("--deactivate-others", help="Deactivate other project versions without 'keepActive' property", type=config.parse_true, nargs='?', const=True, default=True)
    parser.add_argument("--clone", help="Clones the project before uploading a new version", type=config.parse_true, nargs='?', const=True, default=True)

def add_project_params(parser: ArgumentParser):
    add_project_name_params(parser)
    add_project_identity_params(parser)
    add_project_version_params(parser)

def add_project_name_params(parser: ArgumentParser):
    parser.add_argument("--project-name", help="Project name", required=False)

def add_project_identity_params(parser: ArgumentParser):
    parser.add_argument("--project-uuid", help="Project UUID", required=False)

def add_project_version_params(parser: ArgumentParser):
    parser.add_argument("--project-version", help="Project version", required=False)
    parser.add_argument("--latest", help="Project version is latest", action='store_true', default=False)

def add_property_identifier_params(parser: ArgumentParser):
    parser.add_argument("--property-name", help="Property name")
    parser.add_argument("--group-name", help="Property group name", default=models.program_name)

def create_parser():
    parser = argparse.ArgumentParser(
        prog=models.program_name,
        description="OWASP Dependency Track CLI",
        exit_on_error=False
    )
    parser.add_argument("--env", help="Environment file to load", type=pathlib.Path, default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)

    test = subparsers.add_parser("test", help="Uploads a SBOM, analyzes and reports the according project")
    add_sbom_file(test)
    add_upload_params(test)
    test.set_defaults(func=handle_test)

    upload = subparsers.add_parser("upload", help="Uploads a SBOM only as new active project version (requires permission: BOM_UPLOAD)")
    add_sbom_file(upload)
    add_upload_params(upload)
    upload.set_defaults(func=handle_upload)

    analyze = subparsers.add_parser("analyze", help="Analyzes and reports a project")
    add_project_params(analyze)
    analyze.set_defaults(func=handle_analyze)

    report = subparsers.add_parser("report", help="Creates a report only (requires permissions: VIEW_POLICY_VIOLATION, VIEW_VULNERABILITY)")
    add_project_params(report)
    report.set_defaults(func=handle_report)

    metrics = subparsers.add_parser("metrics", help="Provides metrics (requires permissions: VIEW_POLICY_VIOLATION, VIEW_VULNERABILITY)")
    metrics_sub_parsers = metrics.add_subparsers(dest="type", required=True)
    prometheus = metrics_sub_parsers.add_parser("prometheus", help="Provides Prometheus metrics for findings and violations")
    prometheus.add_argument("--serve", help="Setup a HTTP server", action='store_true', default=False)
    prometheus.add_argument("--serve-port", help="Metrics HTTP server port", type=int, default=8198)
    prometheus.add_argument("--scrape-interval", help="Metrics scrape interval in seconds", type=int, default=3600)
    metrics.set_defaults(func=handle_prometheus_metrics)

    project = subparsers.add_parser("project", help="Manipulate project data. Requires permission: PORTFOLIO_MANAGEMENT")
    project_sub_parsers = project.add_subparsers(dest="type", required=True)
    upsert = project_sub_parsers.add_parser("upsert", help="Creates or patches a project by JSON data and prints the UUID to stdout")
    upsert.add_argument("--file", help="Project JSON file", type=str, required=False)
    upsert.add_argument("--json", help="Project JSON data as string", required=False)
    add_project_params(upsert)
    upsert.set_defaults(func=handle_project_upsert)

    remove_property = project_sub_parsers.add_parser("remove-property", help="Removes a property from a project")
    add_property_identifier_params(remove_property)
    add_project_params(remove_property)
    remove_property.set_defaults(func=handle_project_property_remove)

    activate_project = project_sub_parsers.add_parser("activate", help="Activates a project and sets the 'keepActive' property")
    add_project_params(activate_project)
    activate_project.set_defaults(func=handle_project_activate)

    deactivate_project = project_sub_parsers.add_parser("deactivate", help="Deactivates a project and removes the 'keepActive' property")
    add_project_params(deactivate_project)
    deactivate_project.set_defaults(func=handle_project_deactivate)

    delete_inactive = project_sub_parsers.add_parser("delete-inactive", help="Deletes inactive projects. Requires permission: PORTFOLIO_MANAGEMENT")
    add_project_name_params(delete_inactive)
    delete_inactive.set_defaults(func=handle_project_cleanup)

    return parser
