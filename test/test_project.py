import json
import random
from pathlib import Path

import pytest
from owasp_dt.api.project import get_project
from tinystream import Opt

from owasp_dt_cli.api import create_client_from_env
from owasp_dt_cli.args import create_parser

__base_dir = Path(__file__).parent

__project_uuid = None

@pytest.fixture
def parser():
    yield create_parser()

@pytest.fixture
def client():
    yield create_client_from_env()

def test_create_project_from_file(parser, capsys):
    global __project_uuid
    args = parser.parse_args([
        "project",
        "upsert",
        "--file",
        str(__base_dir / "files/project.json")
    ])

    args.func(args)
    captured = capsys.readouterr()
    __project_uuid = captured.out.strip()
    assert len(__project_uuid) == 36

def test_create_project_from_file_again(parser, capsys):
    test_create_project_from_file(parser, capsys)

@pytest.mark.depends(on=["test_create_project_from_file"])
def test_patch_project_from_string(parser, capsys, client):

    test_tag_name = f"Test-Tag-{random.randrange(0,99999)}"

    project_patch = {
        "tags": [
            { "name": test_tag_name }
        ]
    }

    args = parser.parse_args([
        "project",
        "upsert",
        "--project-uuid",
        __project_uuid,
        "--json",
        json.dumps(project_patch)
    ])

    args.func(args)
    captured = capsys.readouterr()
    project_uuid = captured.out.strip()
    assert len(project_uuid) == 36

    resp = get_project.sync_detailed(project_uuid, client=client)
    project = resp.parsed
    opt_tag = Opt(project).map_key("tags").stream().filter_key_value("name", test_tag_name.lower()).next()
    assert opt_tag.present
