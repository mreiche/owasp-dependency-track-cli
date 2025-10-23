import pytest


@pytest.mark.depends(on=["test/test_upload_analyze_report.py::test_report_by_name"])
def test_prometheus(capsys, parser):
    args = parser.parse_args([
        "metrics",
        "prometheus",
    ])

    args.func(args)

    captured = capsys.readouterr()
    assert "owasp_dtrack_cvss_score" in captured.out
    assert "owasp_dtrack_policy_violations" in captured.out
