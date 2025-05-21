from pathlib import Path

from common import load_env
from lib.args import create_parser

__base_dir = Path(__file__).parent

def setup_module():
    load_env()

def test_test():
    parser = create_parser()
    args = parser.parse_args([
        "test",
        "--project-name",
        "test-project",
        "--auto-create",
        "--latest",
        str(__base_dir / "test.sbom.xml"),
    ])

    args.func(args)
