import pytest

from owasp_dt_cli import cli


def test_cli():
    with pytest.raises(expected_exception=SystemExit) as e:
        cli.run()

    assert e.value.code == 1
