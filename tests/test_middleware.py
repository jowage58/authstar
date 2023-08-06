import pytest

from authstar.middleware import (
    header_value_from,
    parse_auth_header_value,
)


@pytest.fixture()
def test_scope():
    return {
        "headers": [
            (b"authorization", b"Bearer foobar"),
            (b"x-multi-value", b"first"),
            (b"x-multi-value", b"second"),
        ]
    }


def test_header_value_from_case_insensitive(test_scope):
    val = header_value_from(test_scope, "AUTHORIZATION")
    assert val == "Bearer foobar"


def test_header_value_from_missing(test_scope):
    val = header_value_from(test_scope, "does-not-exist")
    assert val is None


def test_header_value_from_returns_first(test_scope):
    val = header_value_from(test_scope, "x-multi-value")
    assert val == "first"


def test_parse_auth_header_value_bearer():
    val = parse_auth_header_value("Bearer sekret")
    assert val.scheme == "bearer"
    assert val.token == "sekret"


def test_parse_auth_header_value_basic():
    val = parse_auth_header_value("Basic sekret")
    assert val.scheme == "basic"
    assert val.token == "sekret"


def test_parse_auth_header_value_invalid():
    val = parse_auth_header_value("sekret")
    assert val is None
