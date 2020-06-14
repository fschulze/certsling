from .acmesession import b64
from .utils import fatal, fatal_response, is_expired, yesno
from functools import partial
import click
import dns.name
import hashlib
import json
import requests
import time


TERMS = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"


class ACMEUris:
    def __init__(self, ca, session):
        self.session = session
        res = session.get(ca + '/directory')
        content_type = res.headers.get('Content-Type')
        if res.status_code != 200 or content_type != 'application/json':
            fatal_response(
                "Couldn't get directory from CA server '%s'" % ca, res)
        self.uris = res.json()
        self.authz_get = session.get
        self.challenge_get = session.get
        self.challenge_post = session.post_signed
        self.new_reg = partial(session.post_signed, self.uris['new-reg'])
        self.new_authz = partial(session.post_signed, self.uris['new-authz'])
        self.new_cert = partial(session.post_signed, self.uris['new-cert'])
        self.reg_post = session.post_signed

    def authorization(self, token):
        return "{}.{}".format(token, self.session.thumbprint)


class ACME:
    def __init__(self, authz_info, acme_uris, challenges, tokens):
        self.authz_info = authz_info
        self.challenges = challenges
        self.acme_uris = acme_uris
        self.tokens = tokens

    def reg_post(self, uri, **kw):
        response = self.acme_uris.reg_post(uri, **kw)
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
            response = self.acme_uris.reg_post(
                uri,
                agreement=terms_uri,
                **kw)
            if response.status_code != 202:
                fatal_response("Got error while updating registration", response)
            data = response.json()
        return data

    def new_reg_post(self, email):
        response = self.acme_uris.new_reg(
            resource="new-reg",
            contact=["mailto:" + email])
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
        response = self.acme_uris.new_authz(
            resource="new-authz",
            identifier=dict(
                type="dns",
                value=domain))
        data = response.json()
        if response.status_code == 201:
            return response.headers['Location'], data
        fatal_response("Got error during new-authz", response)

    def authz_get(self, uri):
        response = self.acme_uris.authz_get(uri)
        data = response.json()
        if response.status_code == 200:
            return data
        fatal_response('Got error reading authz info %s' % uri, response)

    def challenge_get(self, uri):
        response = self.acme_uris.challenge_get(uri)
        data = response.json()
        if response.status_code == 202:
            return data
        fatal_response('Got error reading challenge info %s' % uri, response)

    def challenge_post(self, challenge, domain):
        authorization = self.acme_uris.authorization(challenge['token'])
        if challenge['type'] == 'dns-01':
            digest = hashlib.sha256(authorization.encode('ascii')).digest()
            txt = b64(digest)
            click.echo('_acme-challenge.%s. IN TXT "%s"' % (domain, txt))
            self.tokens[dns.name.from_text(domain)] = txt
        elif challenge['type'] == 'http-01':
            self.tokens[challenge['token']] = authorization.encode('ascii')
        response = self.acme_uris.challenge_post(
            challenge['uri'],
            resource="challenge",
            type=challenge['type'],
            keyAuthorization=authorization)
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

    def challenge_info(self, domain):
        authz_info = self.authz_info.load(domain)
        challenge_info = {}
        if 'authz-uri' in authz_info:
            challenge_info = self.authz_get(authz_info['authz-uri'])
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
            self.authz_info.dump(domain, authz_info)
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
        response = self.acme_uris.new_cert(
            resource="new-cert",
            csr=b64(der))
        links = []
        if 'link' in response.headers:
            links = requests.utils.parse_header_links(response.headers['Link'])
        content_type = response.headers.get('Content-Type')
        if response.status_code == 201 and content_type == 'application/pkix-cert':
            return response.content, links
        fatal_response("Got error during new-authz", response)
