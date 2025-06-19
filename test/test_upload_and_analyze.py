import random
from pathlib import Path

import pytest

from owasp_dt_cli.args import create_parser

__base_dir = Path(__file__).parent

__version = f"v{random.randrange(0, 99999)}"

@pytest.mark.parametrize("version", [ __version ])
def test_upload(version: str):
    parser = create_parser()
    args = parser.parse_args([
        "upload",
        "--project-name",
        "test-upload",
        "--auto-create",
        "--project-version",
        version,
        str(__base_dir / "files/test.sbom.xml"),
    ])

    args.func(args)

@pytest.mark.depends(on=['test_upload'])
@pytest.mark.parametrize("version", [ __version ])
def test_analyze(version: str):
    parser = create_parser()
    args = parser.parse_args([
        "analyze",
        "--project-name",
        "test-upload",
        "--project-version",
        version,
    ])
    args.func(args)
