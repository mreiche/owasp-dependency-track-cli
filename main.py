import argparse
import enum
import pathlib

from features.convert import handle_convert
from features.test import handle_test

def add_sbom_file(parser, default="sbom.json"):
    parser.add_argument("sbom", help="SBOM file path", type=pathlib.Path, default=default)

parser = argparse.ArgumentParser(description="OWASP Dependency Track CLI")
#parser.add_argument("--sbom", help="SBOM file path", default="katze")
subparsers = parser.add_subparsers(dest="command", required=True)

parser_convert = subparsers.add_parser("convert", help="Converting SBOM to XML/JSON")
add_sbom_file(parser_convert)
parser_convert.set_defaults(func=handle_convert)

parser_upload = subparsers.add_parser("test", help="Uploads and tests a SBOM. Requires permission: BOM_UPLOAD")
add_sbom_file(parser_upload)
parser_upload.add_argument("--auto_create", help="Requires permission: PROJECT_CREATION_UPLOAD")
parser_upload.set_defaults(func=handle_test)

# class CreateTypes(enum.Enum):
#     ENV = "environment"
#     PIPENV = "pipenv"
#     REQ = "requirements"
#     POETRY = "poetry"
#
#     def __str__(self):
#         return self.value  # damit argparse die Namen schön darstellt
#
# parser_create = subparsers.add_parser("create", help="Creates a SBOM of a Python project")
# parser_create.add_argument(
#     "type",
#     type=CreateTypes,
#     choices=list(CreateTypes),
#     help="cyclonedx-bom generate command"
# )
# add_sbom_file(parser_create)
#
# parser_create.set_defaults(func=handle_create)

# Parsen und aufrufen
args = parser.parse_args()
args.func(args)
