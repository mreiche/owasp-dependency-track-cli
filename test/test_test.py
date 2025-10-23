from pathlib import Path

import pytest
from owasp_dt import Client

from owasp_dt_cli import api
from owasp_dt_cli.common import retry

__base_dir = Path(__file__).parent


def assert_test(capsys, parser):
    args = parser.parse_args([
        "test",
        "--project-name",
        "test-project",
        "--auto-create",
        "--latest",
        "--project-version",
        "latest",
        str(__base_dir / "files/test.sbom.xml"),
    ])

    assert args.latest == True
    assert args.project_version == "latest"

    args.func(args)
    captured = capsys.readouterr()
    assert "CVE-2018-20225" in captured.out
    assert "Forbid MIT license" in captured.out


@pytest.mark.depends(on=["test/test_api.py::test_create_test_policy", "test/test_api.py::test_get_vulnerabilities"])
@pytest.mark.xfail(reason="https://github.com/DependencyTrack/dependency-track/issues/5401")
def test_test(capsys, parser):
    retry(lambda: assert_test(capsys, parser), 10, 2)


@pytest.mark.depends(on=['test_test'])
def test_vulnerability_severity_threshold(monkeypatch, parser):
    monkeypatch.setenv("SEVERITY_THRESHOLD_HIGH", "1")

    args = parser.parse_args([
        "analyze",
        "--project-name",
        "test-project",
        "--latest"
    ])

    with pytest.raises(ValueError, match="SEVERITY_THRESHOLD_HIGH hit: 1"):
        args.func(args)


@pytest.mark.depends(on=['test_test'])
def test_vulnerability_cvss_threshold(monkeypatch, parser):
    monkeypatch.setenv("CVSS_V3_THRESHOLD", "20")

    args = parser.parse_args([
        "analyze",
        "--project-name",
        "test-project",
        "--latest"
    ])

    with pytest.raises(ValueError, match="CVSS_V3_THRESHOLD hit: 27.8"):
        args.func(args)


@pytest.mark.depends(on=['test_test'])
def test_uploaded(client: Client):
    project = api.find_project_by_name(client=client, name="test-project")
    assert project is not None
    assert project.version == "latest"
    assert project.is_latest == True
