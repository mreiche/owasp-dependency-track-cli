from owasp_dt.types import Unset

from owasp_dt_cli.report import filter_unset


def test_filter_unset():
    assert filter_unset(1) == 1
    assert filter_unset(None) is None
    assert filter_unset("something") == "something"
    assert filter_unset(False) == False
    assert filter_unset(True) == True
    assert filter_unset(Unset) == Unset