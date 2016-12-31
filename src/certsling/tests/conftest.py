import base64
import binascii
import http.server
import json
import pytest
import threading


def d64(data):
    for pad in ('', '=', '=='):
        try:
            return base64.urlsafe_b64decode(data + pad)
        except binascii.Error:
            pass


class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/directory':
            self.send_response(200)
            self.send_header('Replay-Nonce', 'nonce')
            methods = ['new-authz', 'new-cert', 'new-reg']
            addr = "http://%s:%s/{0}" % self.server.socket.getsockname()
            self.write_response({x: addr.format(x) for x in methods})
        else:
            raise ValueError("GET %s" % self.path)

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
        if self.path == '/new-authz':
            payload = self.get_payload()
            self.send_response(201)
            self.send_header('Location', '')
            self.write_response({'status': 'valid'})
        elif self.path == '/new-cert':
            payload = self.get_payload()
            self.send_response(201)
            self.send_header('Content-Type', 'application/pkix-cert')
            self.end_headers()
            self.wfile.write(b'cert')
        elif self.path == '/new-reg':
            payload = self.get_payload()
            protected = self.get_protected()
            self.send_response(200)
            self.write_response({
                'createdAt': 'createdAt',
                'initialIp': 'initialIp',
                'contact': payload['contact'],
                'key': protected['jwk']})
        else:
            raise ValueError("POST %s" % self.path)

    def log_request(self, code):
        return


@pytest.fixture
def server():
    address = ('localhost', 0)
    server = http.server.HTTPServer(address, HTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.fixture
def ca(server):
    return "http://%s:%s" % server.socket.getsockname()


@pytest.fixture(autouse=True)
def genkey(monkeypatch):
    from certsling import genkey
    from functools import partial
    genkey_partial = partial(genkey, keylen=512)
    monkeypatch.setattr("certsling.genkey", genkey_partial)
    return genkey_partial


@pytest.fixture
def base(tmpdir):
    from pathlib import Path
    return Path(tmpdir.ensure_dir('foo@example.com').strpath)


@pytest.fixture
def yesno_true(monkeypatch):
    monkeypatch.setattr("certsling.yesno", lambda *x: True)


@pytest.fixture
def verify_crt_true(monkeypatch):
    monkeypatch.setattr("certsling.verify_crt", lambda *x: True)
