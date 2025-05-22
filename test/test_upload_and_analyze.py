from pathlib import Path

import pytest

from common import load_env
from owasp_dt_cli.args import create_parser

__base_dir = Path(__file__).parent

def setup_module():
    load_env()

def test_upload():
    parser = create_parser()
    args = parser.parse_args([
        "upload",
        "--project-name",
        "test-upload",
        "--auto-create",
        "--latest",
        "--project-version",
        "katze",
        str(__base_dir / "test.sbom.xml"),
    ])

    args.func(args)

@pytest.mark.depends(on=['test_upload'])
def test_analyze():
    parser = create_parser()
    args = parser.parse_args([
        "analyze",
        "--project-name",
        "test-upload",
        "--project-version",
        "katze",
        "--latest",
    ])

    args.func(args)
