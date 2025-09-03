import pytest

from owasp_dt_cli.api import create_client_from_env
from owasp_dt_cli.args import create_parser


@pytest.fixture
def client():
    yield create_client_from_env()

@pytest.fixture
def parser():
    yield create_parser()
