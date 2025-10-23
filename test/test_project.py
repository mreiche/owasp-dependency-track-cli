import json
import random
from pathlib import Path

import pytest
from owasp_dt.api.project import get_project
from tinystream import Opt

__base_dir = Path(__file__).parent

__project_uuid = None


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
    test_tag_name = f"Test-Tag-{random.randrange(0, 99999)}"

    project_patch = {
        "tags": [
            {"name": test_tag_name}
        ],
        "properties": [
            {
                "groupName": "owasp-dtrack-cli-test",
                "propertyName": "test_patch_project_properties",
                "propertyType": "STRING",
                "propertyValue": "success",
            },
        ],
        "active": False
    }

    args = parser.parse_args([
        "project",
        "upsert",
        "--project-uuid",
        __project_uuid,
        "--latest",
        "--json",
        json.dumps(project_patch)
    ])

    args.func(args)
    captured = capsys.readouterr()
    project_uuid = captured.out.strip()
    assert len(project_uuid) == 36

    resp = get_project.sync_detailed(project_uuid, client=client)
    project = resp.parsed
    assert project.is_latest is True
    assert project.active is False

    opt_tag = Opt(project).map_key("tags").stream().filter_key_value("name", test_tag_name.lower()).next()
    assert opt_tag.present

    opt_property = Opt(project).map_key("properties").stream().filter_key_value("property_name", "test_patch_project_properties").next()
    assert opt_property.present
    assert opt_property.get().property_value == "success"


@pytest.mark.depends(on=["test_patch_project_from_string"])
def test_update_project_property(parser, capsys, client):
    project_patch = {
        "properties": [
            {
                "groupName": "owasp-dtrack-cli-test",
                "propertyName": "test_patch_project_properties",
                "propertyType": "STRING",
                "propertyValue": "changed",
            },
        ],
        "active": False,
    }

    args = parser.parse_args([
        "project",
        "upsert",
        "--project-uuid",
        __project_uuid,
        "--latest",
        "--json",
        json.dumps(project_patch)
    ])
    args.func(args)

    resp = get_project.sync_detailed(__project_uuid, client=client)
    project = resp.parsed
    assert project.is_latest is True
    assert project.active is False

    opt_property = Opt(project).map_key("properties").stream().filter_key_value("property_name", "test_patch_project_properties").next()
    assert opt_property.present
    assert opt_property.get().property_value == "changed"


@pytest.mark.depends(on=["test_update_project_property"])
def test_remove_project_property(parser, capsys, client):
    args = parser.parse_args([
        "project",
        "remove-property",
        "--project-uuid",
        __project_uuid,
        "--latest",
        "--group-name",
        "owasp-dtrack-cli-test",
        "--property-name",
        "test_patch_project_properties"
    ])

    args.func(args)
    resp = get_project.sync_detailed(__project_uuid, client=client)
    project = resp.parsed

    opt_property = Opt(project).map_key("properties").stream().filter_key_value("property_name", "test_upsert_project_property").next()
    assert opt_property.absent


@pytest.mark.depends(on=["test_remove_project_property"])
def test_activate_project(parser, client):
    args = parser.parse_args([
        "project",
        "activate",
        "--project-uuid",
        __project_uuid,
    ])
    args.func(args)

    resp = get_project.sync_detailed(__project_uuid, client=client)
    project = resp.parsed
    assert project.active is True

    opt_property = Opt(project).map_key("properties").stream().filter_key_value("property_name", "keepActive").next()
    assert opt_property.present
    assert opt_property.get().property_value == "true"


@pytest.mark.depends(on=["test_activate_project"])
def test_deactivate_project(parser, client):
    args = parser.parse_args([
        "project",
        "deactivate",
        "--project-uuid",
        __project_uuid,
    ])
    args.func(args)

    resp = get_project.sync_detailed(__project_uuid, client=client)
    project = resp.parsed
    assert project.active is False

    opt_property = Opt(project).map_key("properties").stream().filter_key_value("property_name", "keepActive").next()
    assert opt_property.absent


@pytest.mark.depends(on=["test_deactivate_project"])
def test_delete_inactive_project_versions(parser, client):
    args = parser.parse_args([
        "project",
        "delete-inactive",
        "--project-name",
        "upsert-project",  # must match name from project.json
    ])

    args.func(args)

    resp = get_project.sync_detailed(__project_uuid, client=client)
    assert resp.status_code == 404


def test_upsert_invalid_json_file(parser, capsys):
    args = parser.parse_args([
        "project",
        "upsert",
        "--project-name",
        "invalid-file",
        "--file",
        str(__base_dir / "test.env")
    ])

    with pytest.raises(expected_exception=Exception, match="Error loading JSON file"):
        args.func(args)


def test_upsert_invalid_json_string(parser, capsys):
    args = parser.parse_args([
        "project",
        "upsert",
        "--project-name",
        "invalid-json",
        "--json",
        "invalid-json"
    ])

    with pytest.raises(expected_exception=Exception, match="Error parsing JSON"):
        args.func(args)
