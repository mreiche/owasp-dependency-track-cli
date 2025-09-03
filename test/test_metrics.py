import pytest

@pytest.mark.depends(on=["test/test_test.py::test_test"])
def test_prometheus(capsys, parser):
    args = parser.parse_args([
        "metrics",
        "prometheus",
    ])

    args.func(args)

    captured = capsys.readouterr()
    assert "owasp_dtrack_cvss_score" in captured.out
    assert "owasp_dtrack_policy_violations" in captured.out
