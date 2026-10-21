import uuid

from owasp_dt.models import PolicyCondition, PolicyConditionOperator, PolicyConditionSubject, Component
from owasp_dt.types import UNSET

from owasp_dt_cli.report import filter_unset, shorten, format_violation_state, format_component_version, \
    format_component_identifier, format_scoring, format_policy_name


def test_filter_unset():
    assert filter_unset(1) == 1
    assert filter_unset(None) is None
    assert filter_unset("something") == "something"
    assert filter_unset(False) == False
    assert filter_unset(True) == True
    assert filter_unset(UNSET) is None

def test_shorten():
    assert shorten("something") == "something"
    assert shorten(UNSET) == ""
    long_text = "abc"*40
    assert shorten(long_text) == f"{long_text[:97]}..."

def test_format_violation_state():
    assert format_violation_state(UNSET) == "?"

def test_format_component_version():
    assert format_component_version(UNSET) == "?"

def test_format_component_identifier():
    assert format_component_identifier(UNSET) == "?"
    component = Component(name="test",group="katze")
    assert format_component_identifier(component) == "katze.test"

def test_format_scoring():
    assert format_scoring(UNSET) == "?"

def test_format_policy_name():
    assert format_policy_name(UNSET) == "?"
    policy_condition = PolicyCondition(
        operator=PolicyConditionOperator.CONTAINS_ALL,
        subject=PolicyConditionSubject.AGE,
        uuid=uuid.uuid4(),
        value=""
    )
    assert format_policy_name(policy_condition) == "?"
