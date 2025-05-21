import argparse
import pathlib
from argparse import ArgumentParser

from owasp_dt_cli.test import handle_test
from owasp_dt_cli.upload import handle_upload


def add_sbom_file(parser: ArgumentParser, default="sbom.json"):
    parser.add_argument("sbom", help="SBOM file path", type=pathlib.Path, default=default)

def add_project_params(parser: ArgumentParser):
    parser.add_argument("--project-uuid", help="Project UUID", required=False)
    parser.add_argument("--project-name", help="Project name", required=False)
    parser.add_argument("--project-version", help="Project version", default="latest")
    parser.add_argument("--latest", help="Project version is latest", action='store_true', default=False)
    parser.add_argument("--auto-create", help="Requires permission: PROJECT_CREATION_UPLOAD", action='store_true', default=False)
    parser.add_argument("--parent-uuid", help="Parent project UUID", required=False)
    parser.add_argument("--parent-name", help="Parent project name", required=False)

def create_parser():
    parser = argparse.ArgumentParser(description="OWASP Dependency Track CLI")
    #parser.add_argument("--sbom", help="SBOM file path", default="katze")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # parser_convert = subparsers.add_parser("convert", help="Converting SBOM to XML/JSON")
    # add_sbom_file(parser_convert)
    # parser_convert.set_defaults(func=handle_convert)

    test = subparsers.add_parser("test", help="Uploads and tests a SBOM and creates a findings report. Requires permission: BOM_UPLOAD")
    add_sbom_file(test)
    add_project_params(test)
    test.set_defaults(func=handle_test)

    upload = subparsers.add_parser("upload", help="Uploads a SBOM only. Requires permission: BOM_UPLOAD")
    add_sbom_file(upload)
    add_project_params(upload)
    upload.set_defaults(func=handle_upload)

    return parser
