from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import OpenSSL
import base64
import binascii
import click
import datetime
import hashlib
import http.server
import json
import requests
import subprocess
import sys
import tempfile
import threading
import time


# CA = "https://acme-staging.api.letsencrypt.org"
CA = "https://acme-v01.api.letsencrypt.org"
CURL = 'curl'
OPENSSL = 'openssl'
OPENSSL_CONF = Path('/usr/local/etc/openssl/openssl.cnf')
TERMS = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"
LETSENCRYPT_CERT = 'lets-encrypt-x1-cross-signed'


def yesno(question, default=None, all=False):
    if default is True:
        question = "%s [Yes/no" % question
        answers = {
            False: ('n', 'no'),
            True: ('', 'y', 'yes'),
        }
    elif default is False:
        question = "%s [yes/No" % question
        answers = {
            False: ('', 'n', 'no'),
            True: ('y', 'yes'),
        }
    else:
        question = "%s [yes/no" % question
        answers = {
            False: ('n', 'no'),
            True: ('y', 'yes'),
        }
    if all:
        if default is 'all':
            answers['all'] = ('', 'a', 'all')
            question = "%s/All" % question
        else:
            answers['all'] = ('a', 'all')
            question = "%s/all" % question
    question = "%s] " % question
    while 1:
        answer = input(question).lower()
        for option in answers:
            if answer in answers[option]:
                return option
        if all:
            print("You have to answer with y, yes, n, no, a or all.", file=sys.stderr)
        else:
            print("You have to answer with y, yes, n or no.", file=sys.stderr)


def fatal(msg, code=3):
    click.echo(click.style(msg, fg='red'))
    sys.exit(code)


def ensure_not_empty(fn):
    if fn.exists():
        with fn.open('rb') as f:
            l = len(f.read().strip())
        if l:
            return True
        fn.unlink()
    return False


def file_generator(base, name):
    def generator(description, ext, generate, *args, **kw):
        fn = base.joinpath("%s%s" % (name, ext))
        rel = fn.relative_to(Path.cwd())
        if ensure_not_empty(fn):
            click.echo(click.style(
                "Using existing %s '%s'." % (description, rel), fg='green'))
            return fn
        click.echo("Writing %s '%s'." % (description, rel))
        generate(fn, *args, **kw)
        return fn
    return generator


def dated_file_generator(base, name, date, current=False):
    def generator(description, ext, generate, *args, **kw):
        fn = base.joinpath("%s%s" % (name, ext))
        rel = fn.relative_to(Path.cwd())
        fn_date = base.joinpath("%s-%s%s" % (name, date, ext))
        rel_date = fn_date.relative_to(Path.cwd())
        if current == 'force' and fn.exists():
            click.echo("Unlinking existing %s '%s'." % (description, rel))
            fn.unlink()
        if ensure_not_empty(fn):
            if not current or fn.resolve() == fn_date:
                click.echo(click.style(
                    "Using existing %s '%s'." % (description, rel), fg='green'))
                return fn
            elif fn.exists():
                click.echo("Unlinking existing %s '%s'." % (description, rel))
                fn.unlink()
        if not ensure_not_empty(fn):
            click.echo("Generating %s '%s'." % (description, rel_date))
            generate(fn_date, *args, **kw)
        if fn_date.exists():
            click.echo("Linking %s '%s'." % (description, rel_date))
            fn.symlink_to(fn_date.name)
        return fn
    return generator


def genkey(fn, ask=False):
    if ask:
        click.echo('There is no user key in the current directory %s.' % Path.cwd())
        if not yesno('Do you want to create a user key?', False):
            fatal('No user key created')
    subprocess.check_call([
        OPENSSL, 'genrsa', '-out', str(fn), '4096'])


def genpub(fn, key):
    subprocess.check_call([
        OPENSSL, 'rsa', '-in', str(key), '-pubout', '-out', str(fn)])


def gencsr(fn, key, domains):
    if len(domains) > 1:
        config_fn = fn.parent.joinpath('openssl.cnf')
        with config_fn.open('wb') as config:
            with OPENSSL_CONF.open('rb') as f:
                data = f.read()
                config.write(data)
                if not data.endswith(b'\n'):
                    config.write(b'\n')
            dns = ','.join('DNS:%s' % x for x in domains)
            lines = ['', '[SAN]', 'subjectAltName = %s' % dns, '']
            config.write(bytes('\n'.join(lines).encode('ascii')))
        subprocess.check_call([
            OPENSSL, 'req', '-sha256', '-new',
            '-key', str(key), '-out', str(fn), '-subj', '/',
            '-reqexts', 'SAN', '-config', str(config_fn)])
    else:
        subprocess.check_call([
            OPENSSL, 'req', '-sha256', '-new',
            '-key', str(key), '-out', str(fn),
            '-subj', '/CN=%s' % domains[0]])


def verify_domains(cert_or_req, domains):
    names = set()
    subject = dict(cert_or_req.get_subject().get_components()).get(
        b'CN', b'').decode('ascii')
    if subject:
        names.add(subject)
    if hasattr(cert_or_req, 'get_extensions'):
        extensions = cert_or_req.get_extensions()
    else:
        extensions = [
            cert_or_req.get_extension(x)
            for x in range(cert_or_req.get_extension_count())]
    for ext in extensions:
        if ext.get_short_name() != b'subjectAltName':
            continue
        alt_names = [
            x.strip().replace('DNS:', '')
            for x in str(ext).split(',')]
        names = names.union(alt_names)
    unmatched = set(domains).difference(names)
    if unmatched:
        click.echo(click.style(
            "Unmatched alternate names %s" % ', '.join(unmatched), fg="red"))
        return False
    return True


def verify_csr(csr, domains):
    subprocess.check_call([
        OPENSSL, 'req', '-noout', '-verify', '-in', str(csr)])
    with csr.open('rb') as f:
        req = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, f.read())
    if not verify_domains(req, domains):
        subprocess.check_call([
            OPENSSL, 'req', '-noout', '-text', '-in', str(csr)])
        return False
    return True


def gender(fn, csr):
    subprocess.check_call([
        OPENSSL, 'req', '-outform', 'DER', '-out', str(fn), '-in', str(csr)])


def b64(data):
    return base64.urlsafe_b64encode(data).replace(b"=", b"").decode('ascii')


class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parts = self.path.split('/')
        if len(parts) != 4 or parts[1:3] != ['.well-known', 'acme-challenge']:
            self.send_response(404)
            self.end_headers()
            return
        token = parts[3]
        if token not in self.server.tokens:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.server.tokens[token])


class ACME:
    def __init__(self, base, priv, pub):
        self.base = base
        self.priv = priv
        self.pub = pub
        self.session = requests.Session()
        res = self.session.head(CA + '/directory')
        res.raise_for_status()
        self.nonce = res.headers['Replay-Nonce']

    def _encode(cls, data):
        def _leading_zeros(arg):
            if len(arg) % 2:
                return '0' + arg
            return arg

        return b64(binascii.unhexlify(
            _leading_zeros(hex(data)[2:].rstrip('L'))))

    def header(self):
        numbers = self.pub.public_numbers()
        return dict(
            alg="RS256",
            jwk=dict(
                kty="RSA",
                e=self._encode(numbers.e),
                n=self._encode(numbers.n)))

    def thumbprint(self):
        return b64(hashlib.sha256(json.dumps(
            self.header()['jwk'],
            sort_keys=True,
            separators=(',', ':')).encode('ascii')).digest())

    def dump(self, data, indent=None):
        return b64(json.dumps(data, sort_keys=True, indent=indent).encode('utf-8'))

    def protected(self):
        data = self.header()
        data['nonce'] = self.nonce
        return self.dump(data, indent=4)

    def sign(self, protected, payload):
        sig_data = "%s.%s" % (protected, payload)
        with tempfile.NamedTemporaryFile(dir=".", prefix="sign_", suffix=".json") as f:
            f.write(sig_data.encode('ascii'))
            f.flush()
            sig_fn = Path(f.name).with_suffix('.sig')
            try:
                subprocess.check_call([
                    OPENSSL, 'dgst', '-sha256', '-sign', 'user.key', '-out', str(sig_fn), f.name])
                with sig_fn.open('rb') as f:
                    sig = f.read()
            finally:
                if sig_fn.exists():
                    sig_fn.unlink()
        return sig

    def request(self, url, payload, expect_error=False):
        protected = self.protected()
        data = dict(
            header=self.header(),
            protected=protected,
            payload=payload,
            signature=b64(self.sign(protected, payload)))
        try:
            res = self.session.post(url, json=data)
            if 'Replay-Nonce' in res.headers:
                self.nonce = res.headers['Replay-Nonce']
            content_type = res.headers.get('Content-Type', '')
            if content_type in ('application/json', 'application/problem+json'):
                resp = res.json()
            elif content_type == 'application/pkix-cert':
                resp = res.content
            if res.status_code == 409:
                if resp.get('detail') == 'Registration key is already in use':
                    click.echo(click.style("Already registered.", fg='green'))
                    return
            res.raise_for_status()
        except:
            if not expect_error:
                click.echo(click.style(
                    'Request to %s failed (%s): %s\n%s' % (
                        url, res.status_code, res.reason,
                        json.dumps(resp, sort_keys=True, indent=4)),
                    fg="red"))
            raise
        return resp

    def reg(self, email):
        self.request(CA + "/acme/new-reg", self.dump(dict(
            resource="new-reg",
            contact=["mailto:" + email],
            agreement=TERMS), indent=4))

    def challenge_info_fn(self, domain):
        return self.base.joinpath("%s.challenge_info.json" % domain)

    def load_challenge_info(self, domain):
        challenge_info_fn = self.challenge_info_fn(domain)
        challenge_info = {}
        if challenge_info_fn.exists():
            with challenge_info_fn.open() as f:
                challenge_info = json.load(f)
        if not all(x['uri'].startswith(CA) for x in challenge_info.get('challenges', [])):
            challenge_info = {}
        if 'expires' in challenge_info:
            expires = datetime.datetime.strptime(
                challenge_info['expires'].split('.')[0],
                '%Y-%m-%dT%H:%M:%S')
            if (expires - datetime.datetime.now()).total_seconds() < 300:
                challenge_info = {}
        return challenge_info

    def dump_challenge_info(self, domain, challenge_info):
        challenge_info_fn = self.challenge_info_fn(domain)
        json_data = json.dumps(challenge_info, sort_keys=True, indent=4)
        with challenge_info_fn.open('w') as f:
            f.write(json_data)
        return challenge_info

    def update_challenge_info(self, domain, updated_challenge):
        challenge_info = self.load_challenge_info(domain)
        challenges = challenge_info.get('challenges', [])
        if not challenges:
            return
        for challenge in challenges:
            if challenge.get('type') == updated_challenge.get('type'):
                if challenge.get('token') == updated_challenge.get('token'):
                    challenge.update(updated_challenge)
        self.dump_challenge_info(domain, challenge_info)

    def challenge_info(self, domain):
        challenge_info = self.load_challenge_info(domain)
        if not challenge_info:
            challenge_info = self.request(CA + "/acme/new-authz", self.dump(dict(
                resource="new-authz",
                identifier=dict(
                    type="dns",
                    value=domain))))
        self.dump_challenge_info(domain, challenge_info)
        return challenge_info

    def authz(self, domain, tokens):
        challenge_info = self.challenge_info(domain)
        challenges = [
            x
            for x in challenge_info['challenges']
            if x['type'] == "http-01"]
        if len(challenges) != 1:
            fatal("Couldn't get 'http-01' challenge")
        challenge = challenges[0]
        authorization = "{}.{}".format(challenge['token'], self.thumbprint())
        tokens[challenge['token']] = authorization.encode('ascii')
        try:
            resp = self.request(
                challenge['uri'],
                self.dump(dict(
                    resource="challenge",
                    keyAuthorization=authorization)),
                expect_error=True)
        except requests.exceptions.HTTPError as e:
            res = e.response
            info = res.json()
            if info.get('status') == 400 and 'Response does not complete challenge' in info['detail']:
                pass
            else:
                fatal('Request to %s failed (%s): %s\n%s' % (
                    challenge['uri'], res.status_code, res.reason,
                    json.dumps(info, sort_keys=True, indent=4)))
        while 1:
            time.sleep(1)
            res = self.session.get(challenge['uri'])
            try:
                if 'Replay-Nonce' in res.headers:
                    self.nonce = res.headers['Replay-Nonce']
                resp = json.loads(res.text)
                res.raise_for_status()
            except:
                fatal('Request to %s failed (%s): %s\n%s' % (challenge['uri'], res.status_code, res.reason, res.text))
            if resp['status'] == 'pending':
                click.echo('Waiting for response ...')
                continue
            elif resp['status'] == 'valid':
                break
            else:
                fatal("Challenge for %s did not pass: %s" % (domain, resp['status']))
        self.update_challenge_info(domain, resp)

    def cert(self, der):
        return self.request(CA + "/acme/new-cert", self.dump(dict(
            resource="new-cert",
            csr=b64(der))))


def gencrt(fn, der, user_key, user_pub, email, domains):
    backend = default_backend()
    with user_key.open('rb') as f:
        priv = serialization.load_pem_private_key(f.read(), None, backend)
    with user_pub.open('rb') as f:
        pub = serialization.load_pem_public_key(f.read(), backend)
    with der.open('rb') as f:
        der_data = f.read()
    base = der.parent
    address = ('localhost', 8080)
    server = http.server.HTTPServer(address, HTTPRequestHandler)
    server.tokens = dict()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    click.echo("Starting server on %s:%s" % address)
    thread.start()
    acme = ACME(base, priv, pub)
    click.echo("Registering at letsencrypt.")
    acme.reg(email)
    click.echo("Preparing challenges for %s." % ', '.join(domains))
    for domain in domains:
        click.echo("Authorizing %s." % domain)
        acme.authz(domain, server.tokens)
    with tempfile.TemporaryFile() as f:
        f.write(acme.cert(der_data))
        f.flush()
        f.seek(0)
        subprocess.check_call([
            OPENSSL, 'x509', '-inform', 'DER', '-outform', 'PEM', '-out', str(fn)],
            stdin=f)


def verify_crt(crt, domains):
    with crt.open('rb') as f:
        cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, f.read())
    issuer = dict(cert.get_issuer().get_components()).get(
        b'CN', b'unkown').decode('ascii')
    if issuer == 'happy hacker fake CA':
        click.echo(click.style("Certificate issued by staging CA!", fg="red"))
    elif issuer == "Let's Encrypt Authority X1":
        click.echo(click.style("Certificate issued by: %s" % issuer, fg="green"))
    else:
        click.echo(click.style("Unknown CA: %s" % issuer, fg="red"))
    if not verify_domains(cert, domains):
        subprocess.check_call([
            OPENSSL, 'x509', '-noout', '-text', '-in', str(crt)])
        return False
    return True


def getpem(fn):
    subprocess.check_call([
        CURL, '-o', str(fn), 'https://letsencrypt.org/certs/%s.pem' % LETSENCRYPT_CERT])


def chain(fn, crt, pem):
    with fn.open('wb') as out:
        for name in (crt, pem):
            with name.open('rb') as f:
                data = f.read()
                out.write(data)
                if not data.endswith(b'\n'):
                    out.write(b'\n')


def remove(base, *patterns):
    files = []
    for pattern in patterns:
        for fn in base.glob(pattern):
            files.append(fn)
            click.echo(fn.relative_to(Path.cwd()))
    if not yesno("Do you want to remove the above invalid files for a clean retry?"):
        fatal('Aborted.')
    for fn in files:
        if fn.exists():
            fn.unlink()


def generate(base, domains, multi, regenerate):
    user_key = file_generator(base, 'user')(
        'private user key', '.key', genkey, ask=True)
    user_pub = file_generator(base, 'user')(
        'public user key', '.pub', genpub, user_key)
    domains = sorted(domains, key=len)
    main = domains[0]
    if not multi:
        for domain in domains[1:]:
            if not domain.endswith("." + main):
                fatal("Domain '%s' isn't a subdomain of '%s'.")
    key_base = base.joinpath(main)
    if not key_base.exists():
        key_base.mkdir()
    date = datetime.date.today().strftime("%Y%m%d")
    key = dated_file_generator(key_base, main, date)(
        'key', '.key', genkey)
    current = 'force' if regenerate else True
    date_gen = dated_file_generator(key_base, main, date, current=current)
    csr = date_gen('csr', '.csr', gencsr, key, domains)
    if not verify_csr(csr, domains):
        remove(key_base, '*.csr', '*.crt', '*.der')
    der = date_gen('der', '.der', gender, csr)
    crt = date_gen('crt', '.crt', gencrt, der, user_key, user_pub, base.name, domains)
    if not verify_crt(crt, domains):
        remove(key_base, '*.crt', '*.der')
    pem = dated_file_generator(
        base, LETSENCRYPT_CERT, date)('pem', '.pem', getpem)
    file_generator(key_base, main)(
        'chained crt', '-chained.crt', chain, crt, pem)


@click.command()
@click.option("-m/-w", "--multi/--with-www", default=False)
@click.option(
    "-r/-R", "--regenerate/--dont-regenerate", default=False,
    help="Force creating a new certificate even if one for the current day exists.")
@click.argument("domains", metavar="[DOMAIN]...", nargs=-1)
def main(domains, multi, regenerate):
    """Creates a certificate for one or more domains.

    By default a new certificate is generated, except when running again on
    the same day."""
    base = Path.cwd()
    if domains:
        generate(base, domains, multi, regenerate)


if __name__ == '__main__':
    main()
