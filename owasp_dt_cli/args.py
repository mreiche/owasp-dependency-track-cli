from owasp_dt_cli.test import handle_test
import argparse
import pathlib

def add_sbom_file(parser, default="sbom.json"):
    parser.add_argument("sbom", help="SBOM file path", type=pathlib.Path, default=default)

def create_parser():
    parser = argparse.ArgumentParser(description="OWASP Dependency Track CLI")
    #parser.add_argument("--sbom", help="SBOM file path", default="katze")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # parser_convert = subparsers.add_parser("convert", help="Converting SBOM to XML/JSON")
    # add_sbom_file(parser_convert)
    # parser_convert.set_defaults(func=handle_convert)

    parser_upload = subparsers.add_parser("test", help="Uploads and tests a SBOM. Requires permission: BOM_UPLOAD")
    add_sbom_file(parser_upload)
    parser_upload.add_argument("--project-uuid", help="Project UUID", required=False)
    parser_upload.add_argument("--project-name", help="Project name", required=False)
    parser_upload.add_argument("--project-version", help="Project version", default="latest")
    parser_upload.add_argument("--latest", help="Project version is latest", action='store_true', default=False)
    parser_upload.add_argument("--auto-create", help="Requires permission: PROJECT_CREATION_UPLOAD", action='store_true', default=False)
    parser_upload.add_argument("--parent-uuid", help="Parent project UUID", required=False)
    parser_upload.add_argument("--parent-name", help="Parent project name", required=False)
    parser_upload.set_defaults(func=handle_test)

    return parser
