import argparse
import pathlib
from argparse import ArgumentParser

from is_empty import empty

from owasp_dt_cli.analyze import handle_analyze
from owasp_dt_cli.test import handle_test
from owasp_dt_cli.upload import handle_upload


def add_sbom_file(parser: ArgumentParser, default="sbom.json"):
    parser.add_argument("sbom", help="SBOM file path", type=pathlib.Path, default=default)

def add_upload_params(parser: ArgumentParser):
    add_project_identity_params(parser)
    parser.add_argument("--auto-create", help="Requires permission: PROJECT_CREATION_UPLOAD", action='store_true', default=False)
    parser.add_argument("--parent-uuid", help="Parent project UUID", required=False)
    parser.add_argument("--parent-name", help="Parent project name", required=False)

def add_project_identity_params(parser: ArgumentParser):
    parser.add_argument("--project-uuid", help="Project UUID", required=False)
    parser.add_argument("--project-name", help="Project name", required=False)
    parser.add_argument("--project-version", help="Project version", default="latest")
    parser.add_argument("--latest", help="Project version is latest", action='store_true', default=False)

def create_parser():
    parser = argparse.ArgumentParser(
        description="OWASP Dependency Track CLI",
        exit_on_error=False
    )
    #parser.add_argument("--sbom", help="SBOM file path", default="katze")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # parser_convert = subparsers.add_parser("convert", help="Converting SBOM to XML/JSON")
    # add_sbom_file(parser_convert)
    # parser_convert.set_defaults(func=handle_convert)

    test = subparsers.add_parser("test", help="Uploads and analyzes a SBOM. Requires permission: BOM_UPLOAD")
    add_sbom_file(test)
    add_upload_params(test)
    test.set_defaults(func=handle_test)

    upload = subparsers.add_parser("upload", help="Uploads a SBOM only. Requires permission: BOM_UPLOAD")
    add_sbom_file(upload)
    add_upload_params(upload)
    upload.set_defaults(func=handle_upload)

    analyze = subparsers.add_parser("analyze", help="Analyzes a projects and creates a findings report. Requires permission: VIEW_POLICY_VIOLATION, VIEW_VULNERABILITY")
    add_project_identity_params(analyze)
    analyze.set_defaults(func=handle_analyze)

    return parser
