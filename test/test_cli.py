import sys

import pytest

from owasp_dt_cli import cli


def test_cli():
    with pytest.raises(expected_exception=SystemExit) as e:
        cli.main()

    assert e.value.code == 1

def test_cli_with_invalid_env_fails():
    sys.argv = [
        "owasp-dt-cli",
        "--env",
        "katze",
        "metrics",
        "prometheus",
    ]
    with pytest.raises(expected_exception=SystemExit) as e:
        cli.main()

    assert e.value.code == 2
