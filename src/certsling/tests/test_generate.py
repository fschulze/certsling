from functools import partial
import pytest


@pytest.fixture
def acme_factory(ca):
    from certsling import ACME
    return partial(
        ACME,
        challenges=[],
        tokens={})


@pytest.fixture
def acme_uris_factory(ca):
    from certsling.acme import ACMEUris
    return partial(
        ACMEUris,
        ca=ca)


@pytest.fixture
def authz_cache_factory(ca):
    from certsling import AuthzCache
    return partial(AuthzCache, ca=ca)


@pytest.fixture
def generate(acme_factory, acme_uris_factory, authz_cache_factory, base):
    from certsling import generate
    return partial(
        generate,
        acme_factory=acme_factory,
        acme_uris_factory=acme_uris_factory,
        authz_cache_factory=authz_cache_factory,
        base=base)


def get_file_gens(date=None, regenerate=False, update_registration=False):
    from certsling import _file_generator, _dated_file_generator
    import datetime

    if date is None:
        date = datetime.date.today().strftime("%Y%m%d")
    current = 'force' if regenerate else True
    return dict(
        file=_file_generator,
        dated=partial(_dated_file_generator, date=date),
        current=partial(_dated_file_generator, date=date, current=current),
        registration=partial(_file_generator, update=update_registration))


def test_user_gen(base, generate, verify_crt_true, yesno_true):
    assert list(base.iterdir()) == []
    domains = ['example.com']
    generate(
        main=domains[0], domains=domains,
        file_gens=get_file_gens())
    fns = list(x.name for x in base.iterdir())
    assert 'user.key' in fns
    assert 'user.pub' in fns
