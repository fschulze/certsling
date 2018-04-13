from .utils import fatal_response
from base64 import urlsafe_b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from functools import partial
import OpenSSL
import binascii
import hashlib
import json
import requests


def b64(data):
    return urlsafe_b64encode(data).replace(b"=", b"").decode('ascii')


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


def get_thumbprint(jwk):
    return b64(hashlib.sha256(json.dumps(
        jwk,
        sort_keys=True,
        separators=(',', ':')).encode('ascii')).digest())


def protected(header, nonce):
    data = dict(header)
    data['nonce'] = nonce
    return b64(json.dumps(data, sort_keys=True, indent=4).encode('utf-8'))


def sign_sha256(sig_data, priv):
    return OpenSSL.crypto.sign(
        priv, sig_data.encode('ascii'), 'sha256')


def dumps(**kw):
    return b64(json.dumps(dict(**kw), sort_keys=True).encode('utf-8'))


def _dumps_signed(nonce, header, sign, **kw):
    payload = dumps(**kw)
    sig_data = "%s.%s" % (protected(header, nonce), payload)
    signature = b64(sign(sig_data))
    data = dict(
        header=dict(header),
        protected=protected(header, nonce),
        payload=payload,
        signature=signature)
    return data


class ACMESession:
    def __init__(self, dumps_signed, thumbprint):
        self.dumps_signed = dumps_signed
        self.thumbprint = thumbprint
        self.session = requests.Session()
        self.session.hooks = dict(response=self.response_hook)
        self.get = self.session.get
        self.post = self.session.post

    def response_hook(self, response, *args, **kwargs):
        if 'Replay-Nonce' in response.headers:
            self.nonce = response.headers['Replay-Nonce']

    def post_signed(self, uri, **kw):
        return self.session.post(
            uri,
            json=self.dumps_signed(self.nonce, **kw))


def get_session(jwk, priv):
    dumps_signed = partial(
        _dumps_signed,
        header=dict(alg="RS256", jwk=dict(jwk)),
        sign=partial(sign_sha256, priv=priv))
    thumbprint = get_thumbprint(jwk)
    return ACMESession(dumps_signed, thumbprint)


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
