import random
from pathlib import Path
from time import sleep

import pytest

from common import load_env
from owasp_dt_cli.args import create_parser

__base_dir = Path(__file__).parent

def setup_module():
    load_env()

__version = f"v{random.randrange(0, 99999)}"

def test_upload():
    parser = create_parser()
    args = parser.parse_args([
        "upload",
        "--project-name",
        "test-upload",
        "--auto-create",
        "--project-version",
        __version,
        str(__base_dir / "test.sbom.xml"),
    ])

    args.func(args)

@pytest.mark.depends(on=['test_upload'])
def test_analyze():
    parser = create_parser()
    exception = None

    for i in range(10):
        try:
            exception = None
            args = parser.parse_args([
                "analyze",
                "--project-name",
                "test-upload",
                "--project-version",
                __version,
            ])
            args.func(args)
            break
        except Exception as e:
            exception = e
        sleep(2)

    if exception:
        raise exception
