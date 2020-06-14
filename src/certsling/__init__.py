from . import acme
from . import acmesession
from .servers import start_servers
from .utils import fatal, is_expired, yesno
from .utils import _file_generator
from .utils import _dated_file_generator
from functools import partial
from pathlib import Path
import OpenSSL
import base64
import click
import datetime
import hashlib
import json
import subprocess


CURL = 'curl'
OPENSSL = 'openssl'
LETSENCRYPT_CERT = 'lets-encrypt-x3-cross-signed'


def genkey(fn, ask=False, keylen=4096):
    if ask:
        click.echo('There is no user key in the current directory %s.' % fn.parent)
        if not yesno('Do you want to create a user key?', False):
            fatal('No user key created')
    subprocess.check_call([
        OPENSSL, 'genrsa', '-out', str(fn), str(keylen)])


def genpub(fn, key):
    subprocess.check_call([
        OPENSSL, 'rsa', '-in', str(key), '-pubout', '-out', str(fn)])


def createSubjectAltName(domains):
    return 'subjectAltName = %s' % ','.join('DNS:%s' % x for x in domains)


def gencsr(fn, key, domains):
    if len(domains) > 1:
        config_fn = fn.parent.joinpath('openssl.cnf')
        with config_fn.open('wb') as config:
            lines = [
                '[ req ]',
                'distinguished_name  = req_distinguished_name',
                '',
                '[ req_distinguished_name ]',
                '',
                '[SAN]',
                createSubjectAltName(domains),
                '']
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


def check_acme_registration(genreg, jwk, file_generator):
    click.echo("Checking registration at letsencrypt.")
    reg_fn = file_generator(
        'registration info', '.json', genreg)
    with reg_fn.open() as f:
        registration_info = json.load(f)
    click.echo("Registered on %s via %s" % (
        registration_info["createdAt"], registration_info["initialIp"]))
    click.echo("Contact: %s" % ", ".join(registration_info["contact"]))
    if 'agreement' in registration_info:
        click.echo("Agreement: %s" % registration_info["agreement"])
    if registration_info['key'] != jwk:
        fatal("The public user key and the registration info don't match.")


class AuthzCache:
    def __init__(self, base, ca, current=False):
        self.base = base.joinpath(
            hashlib.md5(ca.encode('utf-8')).hexdigest())
        self.current = current

    def authz_info_fn(self, domain):
        if not self.base.is_dir():
            self.base.mkdir()
        return self.base.joinpath("%s.authz_info.json" % domain)

    def load(self, domain):
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

    def dump(self, domain, authz_info):
        authz_info_fn = self.authz_info_fn(domain)
        json_data = json.dumps(authz_info, sort_keys=True, indent=4)
        with authz_info_fn.open('w') as f:
            f.write(json_data)
        return authz_info


def _genreg(fn, acme, email):
    data = acme.new_reg_post(email)
    data = json.dumps(data, sort_keys=True, indent=4)
    with fn.open('w') as out:
        out.write(data)


def gencrt(fn, acme_factory, check_registration, der, user_pub, email, domains):
    with der.open('rb') as f:
        der_data = f.read()
    acme = acme_factory()
    genreg = partial(_genreg, acme=acme, email=email)
    check_registration(genreg)
    click.echo("Preparing challenges for %s." % ', '.join(domains))
    for domain in domains:
        click.echo("Authorizing %s." % domain)
        info = acme.handle_authz(domain)
        if info.get('status') != 'valid':
            fatal("Couldn't finish authorization of '%s'." % domain)
    (cert, issuer_cert_links) = acme.new_cert_post(der_data)
    with fn.open('wb') as out:
        out.write(b'-----BEGIN CERTIFICATE-----\n')
        out.write(base64.encodestring(cert))
        out.write(b'-----END CERTIFICATE-----\n')


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
            click.echo(fn.relative_to(base))
    if not yesno("Do you want to remove the above invalid files for a clean retry?"):
        fatal('Aborted.')
    for fn in files:
        if fn.exists():
            fn.unlink()


def generate(base, main, acme_factory, acme_uris_factory, authz_cache_factory, domains, file_gens):
    user_key = file_gens['file'](base, 'user')(
        'private user key', '.key', genkey, ask=True)
    user_pub = file_gens['file'](base, 'user')(
        'public user key', '.pub', genpub, user_key)
    assert user_pub.parent == base
    key_base = base.joinpath(main)
    if not key_base.exists():
        key_base.mkdir()
    key = file_gens['dated'](key_base, main)(
        'key', '.key', genkey)
    date_gen = file_gens['current'](key_base, main)
    while True:
        csr = date_gen('csr', '.csr', gencsr, key, domains)
        if verify_csr(csr, domains):
            break
        remove(key_base, '*.csr', '*.crt', '*.der')
    with user_key.open('rb') as f:
        priv = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, f.read())
    jwk = acmesession.get_jwk(user_pub)
    session = acmesession.get_session(jwk, priv)
    check_registration = partial(
        check_acme_registration,
        jwk=jwk,
        file_generator=file_gens['registration'](base, 'registration'))
    while True:
        der = date_gen('der', '.der', gender, csr)
        assert der.parent == key_base
        acme_factory = partial(
            acme_factory,
            authz_info=authz_cache_factory(base=key_base),
            acme_uris=acme_uris_factory(session=session))
        crt = date_gen('crt', '.crt', gencrt, acme_factory, check_registration, der, user_pub, base.name, domains)
        if verify_crt(crt, domains):
            break
        remove(key_base, '*.crt', '*.der')
    pem = file_gens['dated'](base, LETSENCRYPT_CERT)(
        'pem', '.pem', getpem)
    date_gen('chained crt', '-chained.crt', chain, crt, pem)


def domain_key(x):
    return (len(x), x)


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option(
    "--dns/--no-dns", default=False,
    help="Enable/disable DNS challenge. HTTP challenge is tried first if enabled.")
@click.option(
    "--http/--no-http", default=True,
    help="Enable/disable HTTP challenge.")
@click.option(
    "-r/-R", "--regenerate/--dont-regenerate", default=False,
    help="Force creating a new certificate even if one for the current day exists.")
@click.option(
    "-s/-p", "--staging/--production", default=False,
    help="Use staging server of letsencrypt.org for testing.")
@click.option(
    "-u", "--update", metavar="PATH",
    help="Update the certificates in PATH.")
@click.option(
    "--update-registration/--no-update-registration", default=False,
    help="Force an update of the registration, for example to agree to newer terms of service.")
@click.argument("domains", metavar="[DOMAIN]...", nargs=-1)
def main(domains, dns, http, regenerate, staging, update, update_registration):
    """Creates a certificate for one or more domains.

    By default a new certificate is generated, except when running again on
    the same day."""
    if staging:
        ca = "https://acme-staging.api.letsencrypt.org"
    else:
        ca = "https://acme-v01.api.letsencrypt.org"
    base = Path.cwd()
    date = datetime.date.today().strftime("%Y%m%d")
    current = 'force' if regenerate else True
    file_gens = dict(
        file=_file_generator,
        dated=partial(_dated_file_generator, date=date),
        current=partial(_dated_file_generator, date=date, current=current),
        registration=partial(_file_generator, update=update_registration))
    cli_domains = sorted(domains, key=domain_key)
    challenges = ['http-01']
    if http and 'http-01' not in challenges:
        challenges.append('http-01')
    if not http and 'http-01' in challenges:
        challenges.remove('http-01')
    if dns and 'dns-01' not in challenges:
        challenges.append('dns-01')
    if not dns and 'dns-01' in challenges:
        challenges.remove('dns-01')
    if not challenges:
        fatal("No challenge types enabled.")
    options = dict(challenges=challenges)
    if update:
        path = Path(update).absolute()
        if not path.exists():
            fatal("The path %s doesn't exist." % update)
        base = path.parent
        options_path = path.joinpath('options.json')
        if options_path.exists():
            with options_path.open() as f:
                options.update(json.load(f))
        else:
            options['domains'] = [path.name] + [
                x.name.rsplit('.authz_info.json', 1)[0]
                for x in path.glob('*.authz_info.json')]
            options['main'] = path.name
    option_domains = tuple(
        sorted(set(options.get('domains', [])), key=domain_key))
    if option_domains:
        click.echo(click.style(
            "Existing domains from '%s': %s" % (
                update, ", ".join(option_domains)),
            fg="green"))
        domains = tuple(set(domains).union(option_domains))
    if cli_domains:
        click.echo(click.style(
            "Domains from command line: %s" % ", ".join(cli_domains),
            fg="green"))
        domains = tuple(set(domains).union(cli_domains))
    domains = sorted(domains, key=domain_key)
    main = options.get('main', domains[0] if domains else None)
    tokens = {}
    start_servers(challenges, tokens)
    if domains:
        click.echo(click.style(
            "Domains to update: %s" % ", ".join(domains),
            fg="green"))
        click.echo(click.style(
            "Main domain: %s" % main,
            fg="green"))
        click.echo(click.style(
            "Challenges: %s" % ", ".join(challenges),
            fg="green"))
        if update:
            if not yesno("Do you want to update with the above settings?"):
                fatal('Aborted.')
        authz_cache_factory = partial(
            AuthzCache,
            ca=ca,
            current=current)
        acme_factory = partial(
            acme.ACME,
            challenges=challenges,
            tokens=tokens)
        acme_uris_factory = partial(acme.ACMEUris, ca=ca)
        generate(
            base, main,
            acme_factory, acme_uris_factory, authz_cache_factory,
            domains, file_gens)
        with base.joinpath(main, 'options.json').open("w") as f:
            f.write(json.dumps(
                dict(
                    challenges=challenges,
                    main=main,
                    domains=domains),
                sort_keys=True, indent=4))
    else:
        fatal(
            "No domains given.\n"
            "Use --help to print usage.")


if __name__ == '__main__':
    main()
