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


def dated_file_generator(base, name, date):
    def generator(description, ext, generate, *args, **kw):
        fn = base.joinpath("%s%s" % (name, ext))
        rel = fn.relative_to(Path.cwd())
        if ensure_not_empty(fn):
            click.echo(click.style(
                "Using existing %s '%s'." % (description, rel), fg='green'))
            return fn
        fn_date = base.joinpath("%s-%s%s" % (name, date, ext))
        rel_date = fn_date.relative_to(Path.cwd())
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
    if domains:
        config_fn = fn.parent.joinpath('openssl.cnf')
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
            '-key', str(key), '-out', str(fn), '-subj', '/',
            '-reqexts', 'SAN', '-config', str(config_fn)])
    else:
        subprocess.check_call([
            OPENSSL, 'req', '-sha256', '-new',
            '-key', str(key), '-out', str(fn),
            '-subj', '/CN=%s' % main])


def verify_csr(csr):
    subprocess.check_call([
        OPENSSL, 'req', '-noout', '-verify', '-in', str(csr)])


def gencrt(fn, csr, user_pub, email):
    with fn.open('wb') as f:
        subprocess.check_call([
            'python2.7', str(SIGN_CSR),
            '--public-key', str(user_pub),
            '--email', email,
            str(csr)],
            stdout=f)


def getpem(fn):
    subprocess.check_call([
        CURL, '-o', str(fn), 'https://letsencrypt.org/certs/%s.pem' % main])


def chain(fn, crt, pem):
    with fn.open('wb') as out:
        for name in (crt, pem):
            with name.open('rb') as f:
                data = f.read()
                out.write(data)
                if not data.endswith(b'\n'):
                    out.write(b'\n')


def generate(base, domains):
    user_key = file_generator(base, 'user')(
        'private user key', '.key', genkey, ask=True)
    user_pub = file_generator(base, 'user')(
        'public user key', '.pub', genpub, user_key)
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
    date_gen = dated_file_generator(key_base, main, date)
    key = date_gen('key', '.key', genkey)
    csr = date_gen('csr', '.csr', gencsr, key, domains)
    verify_csr(csr)
    crt = date_gen('crt', '.crt', gencrt, csr, user_pub, base.stem)
    pem = dated_file_generator(
        base, 'lets-encrypt-x1-cross-signed', date)('pem', '.pem', getpem)
    file_generator(key_base, main)(
        'chained crt', '.crt', chain, crt, pem)


@click.command()
@click.argument("domain", nargs=-1)
def main(domain):
    base = Path.cwd()
    if domain:
        generate(base, domain)


if __name__ == '__main__':
    main()
