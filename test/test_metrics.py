from pathlib import Path

import pytest

from common import load_env
from owasp_dt_cli.args import create_parser

__base_dir = Path(__file__).parent

def setup_module():
    load_env()


@pytest.mark.depends(on=["test/test_test.py::test_test"])
def test_prometheus(capsys):
    parser = create_parser()
    args = parser.parse_args([
        "metrics",
        "prometheus",
    ])

    args.func(args)

    captured = capsys.readouterr()
    assert "owasp_dtrack_cvss_score" in captured.out
    assert "owasp_dtrack_policy_violations" in captured.out
