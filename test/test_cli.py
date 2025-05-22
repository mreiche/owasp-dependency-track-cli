from argparse import ArgumentError
from pathlib import Path

import pytest

from owasp_dt_cli import cli

__base_dir = Path(__file__).parent

def test_cli():
    with pytest.raises(expected_exception=ArgumentError):
        cli.run()
