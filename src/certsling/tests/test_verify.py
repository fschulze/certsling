from functools import partial
import base64
import pytest


@pytest.fixture()
def server_key(base, genkey):
    fn = base.joinpath('server.key')
    genkey(fn)
    return fn


@pytest.fixture
def gencsr(base, server_key):
    from certsling import gencsr
    return partial(gencsr, key=server_key)


@pytest.mark.parametrize(['csr_domains', 'verify_domains', 'result'], [
    (['example.com'], ['example.com'], True),
    (['example.com', 'foo.example.com'], ['example.com', 'foo.example.com'], True),
    (['example.com', 'other.org'], ['example.com', 'other.org'], True),
    (['example.com', 'foo.example.com'], ['example.com'], False),
    (['example.com'], ['example.com', 'foo.example.com'], False)])
def test_verify_csr(base, csr_domains, gencsr, result, verify_domains):
    from certsling import verify_csr
    fn = base.joinpath('domain.csr')
    gencsr(fn, domains=csr_domains)
    content = fn.open('r').read().splitlines()
    content = base64.b64decode('\n'.join(content[1:-1]))
    for domain in csr_domains:
        assert domain.encode('ascii') in content
    assert verify_csr(fn, domains=verify_domains) is result
