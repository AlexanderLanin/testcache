import pytest

from gpcache import GPCache


def test_echo():
    GPCache(["echo", "Hello, World!"]).main()
    assert True


@pytest.mark.xfail(reason="print does surprisingly horrible stuff")
def test_print():
    GPCache(["print", "Hello, World!"]).main()
    assert True
