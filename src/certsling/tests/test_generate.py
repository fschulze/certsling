from functools import partial
import pytest


@pytest.fixture
def generate(base, ca):
    from certsling import generate
    return partial(generate, base=base, ca=ca, challenges=[])


def test_user_gen(base, generate, verify_crt_true, yesno_true):
    assert list(base.iterdir()) == []
    generate(domains=['example.com'], regenerate=False, update_registration=False)
    fns = list(x.name for x in base.iterdir())
    assert 'user.key' in fns
    assert 'user.pub' in fns
