from pathlib import Path
import click
import datetime
import subprocess
import sys


BASE = Path(sys.argv[0]).absolute().parent.parent
CURL = 'curl'
OPENSSL = 'openssl'
OPENSSL_CONF = Path('/usr/local/etc/openssl/openssl.cnf')
SIGN_CSR = BASE.joinpath('letsencrypt-nosudo', 'sign_csr.py')


def fatal(msg, code=3):
    click.echo(click.style(msg, fg='red'))
    sys.exit(code)


def genkey(key_base, date, main):
    fn = key_base.joinpath("%s.key" % main)
    if fn.exists():
        print("Using existing key '%s'." % fn.relative_to(Path.cwd()))
        return fn
    fn_date = key_base.joinpath("%s-%s.key" % (main, date))
    if not fn_date.exists():
        print("Generating key '%s'." % fn_date.relative_to(Path.cwd()))
        subprocess.check_call([
            OPENSSL, 'genrsa', '-out', str(fn_date), '4096'])
    if fn_date.exists():
        print("Linking key '%s'." % fn_date.relative_to(Path.cwd()))
        fn.symlink_to(fn_date.name)
    return fn


def gencsr(key_base, date, key, main, domains):
    fn = key_base.joinpath("%s.csr" % main)
    if fn.exists():
        print("Using existing csr '%s'." % fn.relative_to(Path.cwd()))
        return fn
    fn_date = key_base.joinpath("%s-%s.csr" % (main, date))
    if not fn_date.exists():
        print("Generating csr '%s'." % fn_date.relative_to(Path.cwd()))
        if domains:
            config_fn = key_base.joinpath('openssl.cnf')
            with config_fn.open('wb') as config:
                with OPENSSL_CONF.open('rb') as f:
                    data = f.read()
                    config.write(data)
                    if not data.endswith(b'\n'):
                        config.write(b'\n')
                dns = ','.join('DNS:%s' % x for x in [main] + domains)
                lines = ['', '[SAN]', 'subjectAltName = %s' % dns, '']
                config.write(bytes('\n'.join(lines).encode('ascii')))
            subprocess.check_call([
                OPENSSL, 'req', '-sha256', '-new',
                '-key', str(key), '-out', str(fn_date), '-subj', '/',
                '-reqexts', 'SAN', '-config', str(config_fn)])
        else:
            subprocess.check_call([
                OPENSSL, 'req', '-sha256', '-new',
                '-key', str(key), '-out', str(fn_date),
                '-subj', '/CN=%s' % main])
    if fn_date.exists():
        print("Linking csr '%s'." % fn_date.relative_to(Path.cwd()))
        fn.symlink_to(fn_date.name)
    return fn


def verify(csr):
    subprocess.check_call([
        OPENSSL, 'req', '-text', '-noout', '-verify', '-in', str(csr)])


def gencrt(key_base, date, csr, user_pub, main):
    fn = key_base.joinpath("%s.crt" % main)
    if fn.exists():
        print("Using existing crt '%s'." % fn.relative_to(Path.cwd()))
        return fn
    fn_date = key_base.joinpath("%s-%s.crt" % (main, date))
    if not fn_date.exists():
        print("Generating csr '%s'." % fn_date.relative_to(Path.cwd()))
        with fn_date.open('wb') as f:
            subprocess.check_call([
                'python2.7', str(SIGN_CSR),
                '--public-key', str(user_pub), str(csr)],
                stdout=f)
    if fn_date.exists():
        print("Linking crt '%s'." % fn_date.relative_to(Path.cwd()))
        fn.symlink_to(fn_date.name)
    return fn


def getpem(base, date):
    main = 'lets-encrypt-x1-cross-signed'
    fn = base.joinpath("%s.pem" % main)
    if fn.exists():
        print("Using existing pem '%s'." % fn.relative_to(Path.cwd()))
        return fn
    fn_date = base.joinpath("%s-%s.pem" % (main, date))
    if not fn_date.exists():
        print("Generating pem '%s'." % fn_date.relative_to(Path.cwd()))
        subprocess.check_call([
            CURL, '-o', str(fn_date), 'https://letsencrypt.org/certs/%s.pem' % main])
    if fn_date.exists():
        print("Linking pem '%s'." % fn_date.relative_to(Path.cwd()))
        fn.symlink_to(fn_date.name)
    return fn


def chain(key_base, crt, pem, main):
    fn = key_base.joinpath("%s-chained.crt" % main)
    if fn.exists():
        print("Using existing chained crt '%s'." % fn.relative_to(Path.cwd()))
        return fn
    print("Writing chained crt '%s'." % fn.relative_to(Path.cwd()))
    with fn.open('wb') as out:
        for name in (crt, pem):
            with name.open('rb') as f:
                data = f.read()
                out.write(data)
                if not data.endswith(b'\n'):
                    out.write(b'\n')
    return fn


def generate(base, domains):
    user_pub = base.joinpath('user.pub')
    if not user_pub.exists():
        fatal("No 'user.pub' in current directory.", code=10)
    if not SIGN_CSR.exists():
        fatal("No 'letsencrypt-nosudo' in '%s' directory." % BASE, code=10)
    domains = sorted(domains, key=len)
    main, domains = domains[0], domains[1:]
    for domain in domains:
        if not domain.endswith("." + main):
            fatal("Domain '%s' isn't a subdomain of '%s'.")
    key_base = base.joinpath(main)
    if not key_base.exists():
        key_base.mkdir()
    date = datetime.date.today().strftime("%Y%m%d")
    key = genkey(key_base, date, main)
    csr = gencsr(key_base, date, key, main, domains)
    verify(csr)
    crt = gencrt(key_base, date, csr, user_pub, main)
    pem = getpem(base, date)
    chain(key_base, crt, pem, main)


@click.command()
@click.argument("domain", nargs=-1)
def main(domain):
    base = Path.cwd()
    if domain:
        generate(base, domain)


if __name__ == '__main__':
    main()
