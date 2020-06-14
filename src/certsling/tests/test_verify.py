from functools import partial
import base64
import pytest
import subprocess


@pytest.fixture()
def server_key(base, genkey):
    fn = base.joinpath('server.key')
    genkey(fn, yesno=lambda m: True)
    return fn


@pytest.fixture
def gencsr(base, server_key):
    from certsling import gencsr
    return partial(gencsr, key=server_key)


@pytest.fixture()
def ca_key(base, genkey):
    fn = base.joinpath('ca.key')
    genkey(fn, yesno=lambda m: True)
    return fn


@pytest.fixture(params=[
    'Foo',
    'happy hacker fake CA',
    'Fake LE Intermediate X1',
    "Let's Encrypt Authority X1",
    "Let's Encrypt Authority X2",
    "Let's Encrypt Authority X3",
    "Let's Encrypt Authority X4"])
def ca_crt(base, ca_key, request):
    fn = base.joinpath('ca.crt')
    subprocess.check_call([
        'openssl', 'req',
        '-new', '-x509', '-key', str(ca_key), '-out', str(fn),
        '-subj', '/C=DE/CN=%s' % request.param,
        '-days', '90'])
    return fn


@pytest.fixture()
def signer(base, ca_key, ca_crt):
    from certsling import createSubjectAltName

    def signer(csr, crt, domains):
        import textwrap
        conf = base.joinpath('ca.conf')
        conf.open('w').write(textwrap.dedent("""\
        extensions = extend
        [extend] # openssl extensions
        %s
        """ % createSubjectAltName(domains)))
        subprocess.check_call([
            'openssl', 'x509', '-extfile', str(conf),
            '-req', '-CA', str(ca_crt), '-CAkey', str(ca_key),
            '-set_serial', '01', '-in', str(csr), '-out', str(crt),
            '-days', '90'])
    return signer


@pytest.mark.parametrize(['csr_domains', 'verify_domains', 'csr_result', 'crt_result'], [
    (
        ['example.com'],
        ['example.com'],
        True, True),
    (
        ['example.com', 'foo.example.com'],
        ['example.com', 'foo.example.com'],
        True, True),
    (
        ['example.com', 'other.org'],
        ['example.com', 'other.org'],
        True, True),
    (
        ['example.com', 'foo.example.com'],
        ['example.com'],
        False, False),
    (
        ['example.com'],
        ['example.com', 'foo.example.com'],
        False, False)])
def test_verify(base, crt_result, csr_domains, csr_result, gencsr, signer, verify_domains):
    from certsling import verify_crt, verify_csr
    csr_fn = base.joinpath('domain.csr')
    gencsr(csr_fn, domains=csr_domains)
    csr_content = csr_fn.open('r').read().splitlines()
    csr_content = base64.b64decode('\n'.join(csr_content[1:-1]))
    for domain in csr_domains:
        assert domain.encode('ascii') in csr_content
    assert verify_csr(csr_fn, domains=verify_domains) is csr_result
    crt_fn = base.joinpath('domain.crt')
    signer(str(csr_fn), str(crt_fn), csr_domains)
    crt_content = crt_fn.open('r').read().splitlines()
    crt_content = base64.b64decode('\n'.join(crt_content[1:-1]))
    for domain in csr_domains:
        assert domain.encode('ascii') in crt_content
    assert verify_crt(crt_fn, domains=verify_domains) is crt_result
