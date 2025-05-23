from argparse import ArgumentError

import pytest

from owasp_dt_cli import cli


def test_cli():
    with pytest.raises(expected_exception=ArgumentError):
        cli.run()
