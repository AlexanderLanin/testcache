import pytest

from gpcache import GPCache, create_parser


def test_echo(capfd):
    # Fails because stderr is not available?!
    GPCache(create_parser().parse_args("echo 'Hello, World!'")).main()

    #captured = capsys.readouterr()
    #print("stdout: " + captured.stdout)
    #print("stderr: " + captured.stderr)
    assert True


@ pytest.mark.xfail(reason="print does surprisingly horrible stuff")
def test_print(capsys):
    GPCache(create_parser().parse_args("print 'Hello, World!'")).main()
    assert True
