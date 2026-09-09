import pytest
from owasp_dt import utils

from owasp_dt_cli import arguments


@pytest.fixture
def client():
    yield utils.create_client_from_env()


@pytest.fixture(scope="session")
def client_v2():
    yield utils.create_client_from_env("/api/v2")


@pytest.fixture
def parser():
    yield arguments.create_parser()
