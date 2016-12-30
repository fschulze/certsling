from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import OpenSSL
import base64
import binascii
import click
import datetime
import dns.message
import dns.name
import dns.rdtypes.ANY.TXT
import dns.rrset
import hashlib
import http.server
import json
import requests
import socket
import subprocess
import sys
import tempfile
import threading
import time


CURL = 'curl'
OPENSSL = 'openssl'
OPENSSL_CONF = Path('/usr/local/etc/openssl/openssl.cnf')
TERMS = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"
LETSENCRYPT_CERT = 'lets-encrypt-x3-cross-signed'


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


def fatal_response(msg, response, code=3):
    try:
        data = response.json()
    except ValueError:
        data = {}
    headers = '\n'.join(': '.join(x) for x in response.headers.items())
    fatal("%s: %s %s\n%s\n%s" % (
        msg,
        response.status_code, response.reason,
        json.dumps(data, sort_keys=True, indent=4),
        headers))


def get_openssl_conf():
    output = subprocess.check_output([
        OPENSSL, 'version', '-a'])
    ssldir = [x for x in output.splitlines() if x.startswith(b'OPENSSLDIR:')]
    if ssldir:
        ssldir = Path(ssldir[0].decode('utf-8').split(':', 1)[1].strip().strip('"'))
        sslconf = ssldir.joinpath('openssl.cnf')
        if sslconf.exists():
            return sslconf
    return OPENSSL_CONF


def ensure_not_empty(fn):
    if fn.exists():
        with fn.open('rb') as f:
            l = len(f.read().strip())
        if l:
            return True
        fn.unlink()
    return False


def file_generator(base, name, update=False):
    def generator(description, ext, generate, *args, **kw):
        fn = base.joinpath("%s%s" % (name, ext))
        rel = fn.relative_to(Path.cwd())
        if not update and ensure_not_empty(fn):
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
            with get_openssl_conf().open('rb') as f:
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
    unmatched = set(domains).symmetric_difference(names)
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


def dumps(**kw):
    return b64(json.dumps(dict(**kw), sort_keys=True).encode('utf-8'))


def _leading_zeros(arg):
    if len(arg) % 2:
        return '0' + arg
    return arg


def _encode(data):
    return b64(binascii.unhexlify(
        _leading_zeros(hex(data)[2:].rstrip('L'))))


def get_jwk(user_pub):
    backend = default_backend()
    with user_pub.open('rb') as f:
        pub = serialization.load_pem_public_key(f.read(), backend)
        pub_numbers = pub.public_numbers()
        return dict(
            kty="RSA",
            e=_encode(pub_numbers.e),
            n=_encode(pub_numbers.n))


def is_expired(expires):
    expires = datetime.datetime.strptime(
        expires.split('.')[0].rstrip('Z'),
        '%Y-%m-%dT%H:%M:%S')
    return (expires - datetime.datetime.now()).total_seconds() < 300


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


class DNSServer:
    def __init__(self, address):
        self.address = address

    def handle_request(self, addr, data):
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        for question in query.question:
            if question.rdtype != 16:
                continue
            if question.name.labels[0].lower() != b'_acme-challenge':
                continue
            domain = question.name.parent()
            print('Got request from %s for domain %s.' % (addr, domain))
            if domain not in self.tokens:
                continue
            txt = self.tokens[domain]
            print('Answering with "%s" to %s for domain %s.' % (txt, addr, domain))
            response.answer.append(dns.rrset.from_rdata(
                question.name,
                0,
                dns.rdtypes.ANY.TXT.TXT(
                    question.rdclass, question.rdtype, txt)))
        return response.to_wire()

    def __call__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(self.address)
        except OSError as e:
            fatal(str(e))
        s.listen(1)
        while 1:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024)
                reply = self.handle_request(addr, data)
                if reply is not None:
                    conn.send(reply)


class ACME:
    def __init__(self, ca, base, priv, jwk, challenges, current=False):
        self.ca = ca
        self.base = base
        self.priv = priv
        self.jwk = jwk
        self.header = dict(
            alg="RS256",
            jwk=self.jwk.copy())
        self.thumbprint = b64(hashlib.sha256(json.dumps(
            self.jwk,
            sort_keys=True,
            separators=(',', ':')).encode('ascii')).digest())
        self.challenges = challenges
        self.current = current
        self.session = requests.Session()
        self.session.hooks = dict(response=self.response_hook)
        self.uris = {}
        self.tokens = {}

    def response_hook(self, response, *args, **kwargs):
        if 'Replay-Nonce' in response.headers:
            self.nonce = response.headers['Replay-Nonce']

    def update_directory(self):
        res = self.session.get(self.ca + '/directory')
        content_type = res.headers.get('Content-Type')
        if res.status_code != 200 or content_type != 'application/json':
            fatal_response(
                "Couldn't get directory from CA server '%s'" % self.ca, res)
        self.uris.update(res.json())

    def protected(self):
        data = self.header.copy()
        data['nonce'] = self.nonce
        return b64(json.dumps(data, sort_keys=True, indent=4).encode('utf-8'))

    def dumps_signed(self, **kw):
        payload = dumps(**kw)
        protected = self.protected()
        sig_data = "%s.%s" % (protected, payload)
        sig = OpenSSL.crypto.sign(
            self.priv, sig_data.encode('ascii'), 'sha256')
        data = dict(
            header=self.header.copy(),
            protected=protected,
            payload=payload,
            signature=b64(sig))
        return data

    def reg_post(self, uri, **kw):
        response = self.session.post(uri, json=self.dumps_signed(**kw))
        terms_uri = TERMS
        if 'terms-of-service' in response.links:
            terms_uri = response.links['terms-of-service']['url']
        if response.status_code != 202:
            fatal_response("Got error while updating registration", response)
        data = response.json()
        agreement = data.get('agreement')
        if agreement == terms_uri:
            return data
        click.echo("You have previously agreed the following terms:\n%s" % agreement)
        if yesno("Do you now want to agree to the following terms?\n%s" % terms_uri):
            response = self.session.post(
                uri, json=self.dumps_signed(agreement=terms_uri, **kw))
            if response.status_code != 202:
                fatal_response("Got error while updating registration", response)
            data = response.json()
        return data

    def new_reg_post(self, email):
        response = self.session.post(
            self.uris['new-reg'],
            json=self.dumps_signed(
                resource="new-reg",
                contact=["mailto:" + email]))
        if response.status_code == 200:
            info = response.json()
        elif response.status_code == 201:
            uri = response.headers.get('Location', '')
            click.echo("Registration URI: %s" % uri)
            info = self.reg_post(uri, resource="reg")
        elif response.status_code == 409:
            error = response.json()
            if error.get('detail') != 'Registration key is already in use':
                fatal_response("Got error during registration", response)
            click.echo(click.style("Already registered.", fg='green'))
            uri = response.headers.get('Location', '')
            click.echo("Registration URI: %s" % uri)
            info = self.reg_post(uri, resource="reg")
        else:
            fatal_response("Got unknown status during registration", response)
        return info

    def new_authz_post(self, domain):
        response = self.session.post(
            self.uris['new-authz'],
            json=self.dumps_signed(
                resource="new-authz",
                identifier=dict(
                    type="dns",
                    value=domain)))
        data = response.json()
        if response.status_code == 201:
            return response.headers['Location'], data
        fatal_response("Got error during new-authz", response)

    def authz_get(self, uri):
        response = self.session.get(uri)
        data = response.json()
        if response.status_code == 200:
            return data
        fatal_response('Got error reading authz info %s' % uri, response)

    def challenge_get(self, uri):
        response = self.session.get(uri)
        data = response.json()
        if response.status_code == 202:
            return data
        fatal_response('Got error reading challenge info %s' % uri, response)

    def challenge_post(self, challenge, domain):
        authorization = "{}.{}".format(challenge['token'], self.thumbprint)
        if challenge['type'] == 'dns-01':
            digest = hashlib.sha256(authorization.encode('ascii')).digest()
            txt = b64(digest)
            click.echo('_acme-challenge.%s. IN TXT "%s"' % (domain, txt))
            self.tokens[dns.name.from_text(domain)] = txt
        elif challenge['type'] == 'http-01':
            self.tokens[challenge['token']] = authorization.encode('ascii')
        response = self.session.post(
            challenge['uri'],
            json=self.dumps_signed(
                resource="challenge",
                type=challenge['type'],
                keyAuthorization=authorization))
        data = response.json()
        if response.status_code == 202:
            time.sleep(1)
            return data
        if challenge['type'] == 'dns-01':
            del self.tokens[dns.name.from_text(domain)]
        elif challenge['type'] == 'http-01':
            del self.tokens[challenge['token']]
        if response.status_code == 400 and 'Response does not complete challenge' in data['detail']:
            click.echo(click.style(data['detail'], fg="yellow"))
            return
        elif response.status_code == 400 and 'Challenge data was corrupted' in data['detail']:
            click.echo(click.style(data['detail'], fg="yellow"))
            return
        fatal_response(
            'Got error during challenge on %s' % challenge['uri'], response)

    def authz_info_fn(self, domain):
        return self.base.joinpath("%s.authz_info.json" % domain)

    def load_authz_info(self, domain):
        authz_info_fn = self.authz_info_fn(domain)
        authz_info = {}
        if self.current is True and authz_info_fn.exists():
            click.echo(click.style(
                "Using existing challenge info for '%s'." % domain, fg="green"))
            with authz_info_fn.open() as f:
                authz_info = json.load(f)
        if 'authz-uri' not in authz_info:
            authz_info = {}
        if 'expires' in authz_info:
            if is_expired(authz_info['expires']):
                authz_info = {}
        return authz_info

    def dump_authz_info(self, domain, authz_info):
        authz_info_fn = self.authz_info_fn(domain)
        json_data = json.dumps(authz_info, sort_keys=True, indent=4)
        with authz_info_fn.open('w') as f:
            f.write(json_data)
        return authz_info

    def challenge_info(self, domain):
        authz_info = self.load_authz_info(domain)
        challenge_info = {}
        if 'authz-uri' in authz_info:
            if authz_info['authz-uri'].startswith(self.ca):
                challenge_info = self.authz_get(authz_info['authz-uri'])
            else:
                challenge_info = {}
            if 'expires' in challenge_info:
                if is_expired(challenge_info['expires']):
                    challenge_info = {}
            status = challenge_info.get('status', 'pending')
            if status not in ('pending', 'valid'):
                challenge_info = {}
        if not challenge_info:
            authz_uri, challenge_info = self.new_authz_post(domain)
            authz_info['authz-uri'] = authz_uri
            if 'expires' in challenge_info:
                authz_info['expires'] = challenge_info['expires']
            self.dump_authz_info(domain, authz_info)
        return challenge_info

    def wait_for_challenge_response(self, uri, timeout):
        while timeout:
            data = self.challenge_get(uri)
            if data['status'] == 'pending':
                click.echo('Waiting for response ...')
                time.sleep(1)
                timeout = timeout - 1
                continue
            return data

    def handle_challenge(self, uri, domain):
        challenge = self.challenge_get(uri)
        status = challenge.get('status', 'pending')
        if status == 'pending':
            click.echo(click.style(
                "Trying challenge type '%s'." % challenge['type'],
                fg="green"))
            data = self.challenge_post(challenge, domain)
            if data is None:
                return False
            challenge = self.wait_for_challenge_response(uri, 15)
            if challenge is None:
                return False
        if challenge['status'] == 'invalid':
            click.echo(click.style("Challenge invalid.", fg="yellow"))
            if 'error' in challenge and 'detail' in challenge['error']:
                click.echo(click.style(challenge['error']['detail'], fg='yellow'))
            return False
        elif challenge['status'] == 'valid':
            click.echo(click.style("Challenge valid.", fg="green"))
            return True
        elif challenge['status'] == 'pending':
            click.echo(click.style("Challenge pending."), fg="yellow")
            if 'error' in challenge and 'detail' in challenge['error']:
                click.echo(click.style(challenge['error']['detail'], fg='yellow'))
            return False
        elif challenge['status'] != 'valid':
            fatal("Challenge for %s did not pass: %s" % (
                domain, json.dumps(challenge, sort_keys=True, indent=4)))

    def handle_authz(self, domain):
        for challenge_type in self.challenges:
            challenge_info = self.challenge_info(domain)
            if challenge_info.get('status') == 'valid':
                return challenge_info
            challenge = [
                x
                for x in challenge_info['challenges']
                if x['type'] == challenge_type][0]
            if self.handle_challenge(challenge['uri'], domain):
                break
        challenge_info = self.challenge_info(domain)
        return challenge_info

    def new_cert_post(self, der):
        response = self.session.post(
            self.uris['new-cert'],
            json=self.dumps_signed(
                resource="new-cert",
                csr=b64(der)))
        content_type = response.headers.get('Content-Type')
        if response.status_code == 201 and content_type == 'application/pkix-cert':
            return response.content
        fatal_response("Got error during new-authz", response)


def genreg(fn, acme, email):
    data = acme.new_reg_post(email)
    data = json.dumps(data, sort_keys=True, indent=4)
    with fn.open('w') as out:
        out.write(data)


def gencrt(fn, der, user_key, user_pub, email, domains, challenges, ca, update_registration, current=False):
    with user_key.open('rb') as f:
        priv = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, f.read())
    jwk = get_jwk(user_pub)
    with der.open('rb') as f:
        der_data = f.read()
    base = der.parent
    address = ('localhost', 8080)
    server = http.server.HTTPServer(address, HTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    click.echo("Starting http server on %s:%s" % address)
    thread.start()
    time.sleep(0.1)
    dnsaddress = ('localhost', 8053)
    dnsserver = DNSServer(dnsaddress)
    dnsthread = threading.Thread(target=dnsserver, daemon=True)
    click.echo("Starting dns server on %s:%s" % dnsaddress)
    dnsthread.start()
    time.sleep(0.1)
    if not thread.is_alive() or not dnsthread.is_alive():
        fatal("Failed to start servers.")
    acme = ACME(ca, base, priv, jwk, challenges, current=current)
    dnsserver.tokens = server.tokens = acme.tokens
    acme.update_directory()
    click.echo("Checking registration at letsencrypt.")
    reg_fn = file_generator(user_pub.parent, 'registration', update=update_registration)(
        'registration info', '.json', genreg, acme, email)
    with reg_fn.open() as f:
        registration_info = json.load(f)
    click.echo("Registered on %s via %s" % (
        registration_info["createdAt"], registration_info["initialIp"]))
    click.echo("Contact: %s" % ", ".join(registration_info["contact"]))
    if 'agreement' in registration_info:
        click.echo("Agreement: %s" % registration_info["agreement"])
    click.echo("Preparing challenges for %s." % ', '.join(domains))
    if registration_info['key'] != jwk:
        fatal("The public user key and the registration info don't match.")
    for domain in domains:
        click.echo("Authorizing %s." % domain)
        info = acme.handle_authz(domain)
        if info.get('status') != 'valid':
            fatal("Couldn't finish authorization of '%s'." % domain)
    cert = acme.new_cert_post(der_data)
    with tempfile.TemporaryFile() as f:
        f.write(cert)
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
        b'CN', b'unknown').decode('ascii')
    if issuer in ["happy hacker fake CA",
                  "Fake LE Intermediate X1"]:
        click.echo(click.style("Certificate issued by staging CA!", fg="red"))
    elif issuer in ["Let's Encrypt Authority X1",
                    "Let's Encrypt Authority X2",
                    "Let's Encrypt Authority X3",
                    "Let's Encrypt Authority X4"]:
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


def generate(base, domains, challenges, regenerate, ca, update_registration):
    user_key = file_generator(base, 'user')(
        'private user key', '.key', genkey, ask=True)
    user_pub = file_generator(base, 'user')(
        'public user key', '.pub', genpub, user_key)
    domains = sorted(domains, key=len)
    main = domains[0]
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
    crt = date_gen('crt', '.crt', gencrt, der, user_key, user_pub, base.name, domains, challenges, ca, update_registration, current=current)
    if not verify_crt(crt, domains):
        remove(key_base, '*.crt', '*.der')
    pem = dated_file_generator(
        base, LETSENCRYPT_CERT, date)('pem', '.pem', getpem)
    date_gen('chained crt', '-chained.crt', chain, crt, pem)


@click.command()
@click.option(
    "--dns/--no-dns", default=False,
    help="Try DNS challenge if HTTP challenge fails")
@click.option(
    "-r/-R", "--regenerate/--dont-regenerate", default=False,
    help="Force creating a new certificate even if one for the current day exists.")
@click.option(
    "-s/-p", "--staging/--production", default=False,
    help="Use staging server of letsencrypt.org for testing.")
@click.option(
    "--update-registration/--no-update-registration", default=False,
    help="Force an update of the registration, for example to agree to newer terms of service.")
@click.argument("domains", metavar="[DOMAIN]...", nargs=-1)
def main(domains, dns, regenerate, staging, update_registration):
    """Creates a certificate for one or more domains.

    By default a new certificate is generated, except when running again on
    the same day."""
    click.echo(click.style(
        "letsencrypt-remote has been renamed to certsling.\n"
        "For further updates you have to install certsling instead of letsencrypt-remote.",
        fg='red'))
    if staging:
        ca = "https://acme-staging.api.letsencrypt.org"
    else:
        ca = "https://acme-v01.api.letsencrypt.org"
    base = Path.cwd()
    challenges = ['http-01']
    if dns:
        challenges.append('dns-01')
    if domains:
        generate(base, domains, challenges, regenerate, ca, update_registration)


if __name__ == '__main__':
    main()
