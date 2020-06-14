import click
import datetime
import json
import sys


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


def is_expired(expires):
    expires = datetime.datetime.strptime(
        expires.split('.')[0].rstrip('Z'),
        '%Y-%m-%dT%H:%M:%S')
    return (expires - datetime.datetime.now()).total_seconds() < 300


def ensure_not_empty(fn):
    if fn.exists():
        with fn.open('rb') as f:
            l = len(f.read().strip())
        if l:
            return True
        fn.unlink()
    return False


def _file_generator(base, name, update=False):
    def generator(description, ext, generate, *args, **kw):
        fn = base.joinpath("%s%s" % (name, ext))
        rel = fn.relative_to(base)
        if not update and ensure_not_empty(fn):
            click.echo(click.style(
                "Using existing %s '%s'." % (description, rel), fg='green'))
            return fn
        click.echo("Writing %s '%s'." % (description, rel))
        generate(fn, *args, **kw)
        return fn
    return generator


def _dated_file_generator(base, name, date, current=False):
    def generator(description, ext, generate, *args, **kw):
        fn = base.joinpath("%s%s" % (name, ext))
        rel = fn.relative_to(base)
        fn_date = base.joinpath("%s-%s%s" % (name, date, ext))
        rel_date = fn_date.relative_to(base)
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
        if default == 'all':
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
            click.echo("You have to answer with y, yes, n, no, a or all.")
        else:
            click.echo("You have to answer with y, yes, n or no.")
