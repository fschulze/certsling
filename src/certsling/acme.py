from .acmesession import b64
from .utils import fatal, fatal_response
from functools import partial
import click


class ACMEUris:
    def __init__(self, ca, session):
        self.session = session
        res = session.get(ca + '/directory')
        content_type = res.headers.get('Content-Type')
        if res.status_code != 200 or content_type != 'application/json':
            fatal_response(
                "Couldn't get directory from CA server '%s'" % ca, res)
        self.uris = res.json()
        self.terms_uri = self.uris.get('meta', {}).get('termsOfService')
        self.new_account = partial(session.post_jwk_signed, self.uris['newAccount'])
        self.new_nonce = partial(session.head, self.uris['newNonce'])
        self.new_order = partial(session.post_kid_signed, self.uris['newOrder'])


class ACME:
    def __init__(self, acme_uris, challenges, tokens, yesno):
        self.challenges = challenges
        self.acme_uris = acme_uris
        self.tokens = tokens
        self.yesno = yesno

    def authorized_token(self, token):
        return "{}.{}".format(token, self.acme_uris.session.thumbprint).encode('ascii')

    def ensure_account(self):
        self.ensure_nonce()
        if self.acme_uris.session.kid is None:
            res = self.acme_uris.new_account(onlyReturnExisting=True)
            if res.status_code != 200:
                fatal_response("Bad account check response", res)
            self.acme_uris.session.kid = res.headers['Location']

    def ensure_nonce(self):
        if self.acme_uris.session.nonce is None:
            res = self.acme_uris.new_nonce()
            if res.status_code != 204:
                fatal_response("Bad newNonce response", res)

    def finalize_order(self, uri, der_data):
        res = self.acme_uris.session.post_kid_signed(uri, csr=b64(der_data))
        if res.status_code != 200:
            fatal_response("Bad finalize order request", res)
        return res.json()

    def get_certificate(self, uri):
        res = self.acme_uris.session.post_as_get(uri)
        if res.status_code != 200:
            fatal_response("Bad get certificate request", res)
        return res.content

    def handle_authorization(self, uri):
        res = self.acme_uris.session.post_as_get(uri)
        if res.status_code != 200:
            fatal_response("Bad authorization response", res)
        data = res.json()
        if data.get('status') == 'valid':
            self.tokens.set_status(uri, 'valid')
            return
        domain = data['identifier']['value']
        click.echo("Authorizing %s." % domain)
        for challenge_type in self.challenges:
            for challenge in data['challenges']:
                if challenge['type'] != challenge_type:
                    continue
                authorized_token = self.authorized_token(challenge['token'])
                if challenge_type == 'dns-01':
                    self.tokens.add_dns_reply(
                        uri, domain, authorized_token)
                elif challenge_type == 'http-01':
                    self.tokens.add_http_reply(
                        uri, challenge['token'], authorized_token)
                res = self.acme_uris.session.post_kid_signed(challenge['url'])
                if res.status_code != 200:
                    fatal_response("Bad challenge request %s" % challenge, res)

    def handle_order(self, domains):
        self.ensure_account()
        res = self.acme_uris.new_order(identifiers=[
            dict(type="dns", value=domain)
            for domain in domains])
        if res.status_code != 201:
            fatal_response("Bad newOrder response", res)
        return res.headers['Location'], res.json()

    def new_account(self, email):
        self.ensure_nonce()
        question = "Do you agree to the terms of service"
        if self.acme_uris.terms_uri:
            question = "%s at %s" % (question, self.acme_uris.terms_uri)
        if not self.yesno(question):
            fatal("Didn't agree to terms of service.")
        res = self.acme_uris.new_account(
            contact=["mailto:" + email],
            termsOfServiceAgreed=True)
        if res.status_code == 201:
            return res.json()
        fatal_response("Bad newAccount response", res)

    def poll_order(self, uri):
        res = self.acme_uris.session.post_as_get(uri)
        if res.status_code != 200:
            fatal_response("Bad order poll response", res)
        return res.json()
