import pytest

from owasp_dt_cli import api, arguments


@pytest.fixture
def client():
    yield api.create_client_from_env()

@pytest.fixture
def parser():
    yield arguments.create_parser()
