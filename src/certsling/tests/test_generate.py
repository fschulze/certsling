from functools import partial
import pytest


@pytest.fixture
def acme_factory(ca):
    from certsling import ACME
    return partial(
        ACME,
        ca=ca,
        challenges=[],
        tokens={})


@pytest.fixture
def generate(acme_factory, base):
    from certsling import generate
    return partial(generate, acme_factory=acme_factory, base=base)


def test_user_gen(base, generate, verify_crt_true, yesno_true):
    assert list(base.iterdir()) == []
    domains = ['example.com']
    generate(
        main=domains[0], domains=domains,
        regenerate=False)
    fns = list(x.name for x in base.iterdir())
    assert 'user.key' in fns
    assert 'user.pub' in fns
