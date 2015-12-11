import click
import datetime
import os
import subprocess
import sys


BASE = os.path.dirname(os.path.abspath(sys.argv[0]))
CURL = 'curl'
OPENSSL = 'openssl'
OPENSSL_CONF = '/usr/local/etc/openssl/openssl.cnf'
SIGN_CSR = os.path.join(BASE, '..', 'letsencrypt-nosudo', 'sign_csr.py')


def genkey(key_base, date, main):
    fn = os.path.join(key_base, "%s.key" % main)
    if os.path.exists(fn):
        print("Using existing key '%s'." % os.path.relpath(fn))
        return fn
    fn_date = os.path.join(key_base, "%s-%s.key" % (main, date))
    if not os.path.exists(fn_date):
        print("Generating key '%s'." % os.path.relpath(fn_date))
        subprocess.check_call([
            OPENSSL, 'genrsa', '-out', fn_date, '4096'])
    if os.path.exists(fn_date):
        print("Linking key '%s'." % os.path.relpath(fn_date))
        os.symlink(os.path.basename(fn_date), fn)
    return fn


def gencsr(key_base, date, key, main, domains):
    fn = os.path.join(key_base, "%s.csr" % main)
    if os.path.exists(fn):
        print("Using existing csr '%s'." % os.path.relpath(fn))
        return fn
    fn_date = os.path.join(key_base, "%s-%s.csr" % (main, date))
    if not os.path.exists(fn_date):
        print("Generating csr '%s'." % os.path.relpath(fn_date))
        if domains:
            config_fn = os.path.join(key_base, 'openssl.cnf')
            with open(config_fn, 'wb') as config:
                with open(OPENSSL_CONF, 'rb') as f:
                    data = f.read()
                    config.write(data)
                    if not data.endswith(b'\n'):
                        config.write(b'\n')
                dns = ','.join('DNS:%s' % x for x in [main] + domains)
                lines = ['', '[SAN]', 'subjectAltName = %s' % dns, '']
                config.write(bytes('\n'.join(lines).encode('ascii')))
            subprocess.check_call([
                OPENSSL, 'req', '-sha256', '-new',
                '-key', key, '-out', fn_date, '-subj', '/', '-reqexts', 'SAN',
                '-config', config_fn])
        else:
            subprocess.check_call([
                OPENSSL, 'req', '-sha256', '-new',
                '-key', key, '-out', fn_date, '-subj', '/CN=%s' % main])
    if os.path.exists(fn_date):
        print("Linking csr '%s'." % os.path.relpath(fn_date))
        os.symlink(os.path.basename(fn_date), fn)
    return fn


def verify(csr):
    subprocess.check_call([
        OPENSSL, 'req', '-text', '-noout', '-verify', '-in', csr])


def gencrt(key_base, date, csr, user_pub, main):
    fn = os.path.join(key_base, "%s.crt" % main)
    if os.path.exists(fn):
        print("Using existing crt '%s'." % os.path.relpath(fn))
        return fn
    fn_date = os.path.join(key_base, "%s-%s.crt" % (main, date))
    if not os.path.exists(fn_date):
        print("Generating csr '%s'." % os.path.relpath(fn_date))
        with open(fn_date, 'wb') as f:
            subprocess.check_call([
                'python2.7', SIGN_CSR, '--public-key', user_pub, csr],
                stdout=f)
    if os.path.exists(fn_date):
        print("Linking crt '%s'." % os.path.relpath(fn_date))
        os.symlink(os.path.basename(fn_date), fn)
    return fn


def getpem(base, date):
    main = 'lets-encrypt-x1-cross-signed'
    fn = os.path.join(base, "%s.pem" % main)
    if os.path.exists(fn):
        print("Using existing pem '%s'." % os.path.relpath(fn))
        return fn
    fn_date = os.path.join(base, "%s-%s.pem" % (main, date))
    if not os.path.exists(fn_date):
        print("Generating pem '%s'." % os.path.relpath(fn_date))
        subprocess.check_call([
            CURL, '-o', fn_date, 'https://letsencrypt.org/certs/%s.pem' % main])
    if os.path.exists(fn_date):
        print("Linking pem '%s'." % os.path.relpath(fn_date))
        os.symlink(os.path.basename(fn_date), fn)
    return fn


def chain(key_base, crt, pem, main):
    fn = os.path.join(key_base, "%s-chained.crt" % main)
    if os.path.exists(fn):
        print("Using existing chained crt '%s'." % os.path.relpath(fn))
        return fn
    print("Writing chained crt '%s'." % os.path.relpath(fn))
    with open(fn, 'wb') as out:
        for name in (crt, pem):
            with open(name, 'rb') as f:
                data = f.read()
                out.write(data)
                if not data.endswith(b'\n'):
                    out.write(b'\n')
    return fn


def generate(base, domains):
    user_pub = os.path.join(base, 'user.pub')
    if not os.path.exists(user_pub):
        print("No 'user.pub' in current directory.")
        sys.exit(10)
    if not os.path.exists(SIGN_CSR):
        print("No 'letsencrypt-nosudo' in '%s' directory." % BASE)
        sys.exit(10)
    domains = sorted(domains, key=len)
    main, domains = domains[0], domains[1:]
    for domain in domains:
        if not domain.endswith("." + main):
            print("Domain '%s' isn't a subdomain of '%s'.")
            sys.exit(3)
    key_base = os.path.join(base, main)
    if not os.path.exists(key_base):
        os.mkdir(key_base)
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
    base = os.getcwd()
    if domain:
        generate(base, domain)


if __name__ == '__main__':
    main()
