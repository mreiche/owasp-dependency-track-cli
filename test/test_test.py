from pathlib import Path

import httpx
import pytest

from common import load_env
from owasp_dt_cli.args import create_parser

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

def test_proxy_fails(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://localhost:3128")
    with pytest.raises(expected_exception=httpx.ConnectError):
        test_test()
