import base64
import binascii
import http.server
import json
import pytest
import requests
import threading
import time


def d64(data):
    for pad in ('', '=', '=='):
        try:
            return base64.urlsafe_b64decode(data + pad)
        except binascii.Error:
            pass


class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def make_url(self, path):
        addr = "http://%s:%s/{0}" % self.server.socket.getsockname()
        return addr.format(path)

    def do_GET(self):
        if self.path == '/directory':
            self.send_response(200)
            self.send_header('Replay-Nonce', 'nonce')
            methods = ['newAccount', 'newNonce', 'newOrder']
            self.write_response({x: self.make_url(x) for x in methods})
        else:
            raise ValueError("GET %s" % self.path)

    def do_HEAD(self):
        if self.path == '/newNonce':
            self.send_response(200)
            self.send_header('Replay-Nonce', 'nonce')
            self.end_headers()
        else:
            raise ValueError("POST %s" % self.path)

    @property
    def data(self):
        if not hasattr(self, '_data'):
            data = self.rfile.read(int(self.headers['Content-Length']))
            self._data = json.loads(data.decode('utf-8'))
        return self._data

    def get_payload(self):
        payload = d64(self.data['payload'])
        return json.loads(payload.decode('utf-8'))

    def get_protected(self):
        protected = d64(self.data['protected'])
        return json.loads(protected.decode('utf-8'))

    def write_response(self, response):
        response = json.dumps(response)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(response.encode('ascii'))

    def do_POST(self):
        if self.path == '/newOrder':
            payload = self.get_payload()
            self.send_response(201)
            self.send_header('Location', '')
            self.write_response({
                'status': 'valid',
                'certificate': self.make_url('certificate')})
        elif self.path == '/newAccount':
            payload = self.get_payload()
            protected = self.get_protected()
            if 'onlyReturnExisting' in payload:
                if protected['jwk']['n'] in self.server.accounts:
                    self.send_response(200)
                    self.send_header('Location', self.make_url('account/1'))
                    self.end_headers()
                else:
                    self.send_response(400)
                    self.end_headers()
            else:
                self.send_response(201)
                self.write_response({
                    'createdAt': 'createdAt',
                    'initialIp': 'initialIp',
                    'contact': payload['contact'],
                    'key': protected['jwk']})
                self.server.accounts[protected['jwk']['n']] = True
        elif self.path == '/certificate':
            self.send_response(200)
            self.end_headers()
        else:
            raise ValueError("POST %s" % self.path)

    def log_request(self, code):
        return


def wait_for_http(method, url, timeout=60):
    session = requests.Session()
    while timeout > 0:
        try:
            getattr(session, method.lower())(url, timeout=1)
        except ConnectionError:
            time.sleep(1)
            timeout -= 1
        else:
            return
    raise RuntimeError(
        f"The request {method} {url} didn't become accessible")


@pytest.fixture
def server():
    address = ('localhost', 0)
    server = http.server.HTTPServer(address, HTTPRequestHandler)
    server.accounts = {}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    wait_for_http('HEAD', "http://%s:%s/newNonce" % server.socket.getsockname())
    yield server
    server.shutdown()
    thread.join()


@pytest.fixture
def ca(server):
    return "http://%s:%s" % server.socket.getsockname()


@pytest.fixture(autouse=True)
def genkey(monkeypatch):
    from certsling import genrsakey
    from functools import partial
    genkey_partial = partial(genrsakey, keylen=512)
    monkeypatch.setattr("certsling.genrsakey", genkey_partial)
    return genkey_partial


@pytest.fixture
def base(tmpdir):
    from pathlib import Path
    return Path(tmpdir.ensure_dir('foo@example.com').strpath)


@pytest.fixture
def verify_crt_true(monkeypatch):
    monkeypatch.setattr("certsling.verify_crt", lambda *x: True)
