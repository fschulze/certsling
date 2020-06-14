from .acmesession import b64
from .utils import fatal
import click
import dns.name
import dns.message
import dns.rdtypes.ANY.TXT
import dns.rrset
import hashlib
import http.server
import socket
import threading
import time


class Tokens(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._status = {}

    def add_dns_reply(self, uri, domain, authorized_token):
        digest = hashlib.sha256(authorized_token).digest()
        txt = b64(digest)
        click.echo('_acme-challenge.%s. IN TXT "%s"' % (domain, txt))
        self[dns.name.from_text(domain)] = (uri, txt)

    def add_http_reply(self, uri, token, authorized_token):
        self[token] = (uri, authorized_token)

    def set_status(self, uri, status):
        self._status[uri] = status

    def get_status(self, uri):
        return self._status.get(uri, 'unknown')


class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parts = self.path.split('/')
        if len(parts) != 4 or parts[1:3] != ['.well-known', 'acme-challenge']:
            self.send_response(404)
            self.end_headers()
            return
        token = parts[3]
        if token not in self.server.tokens:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        (uri, reply) = self.server.tokens[token]
        self.wfile.write(reply)
        self.server.tokens.set_status(uri, 'requested')


class DNSServer:
    def __init__(self, address):
        self.address = address

    def handle_request(self, addr, data):
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        for question in query.question:
            if question.rdtype != 16:
                continue
            if question.name.labels[0].lower() != b'_acme-challenge':
                continue
            domain = question.name.parent()
            print('Got request from %s for domain %s.' % (addr, domain))
            if domain not in self.tokens:
                continue
            (uri, txt) = self.tokens[domain]
            print('Answering with "%s" to %s for domain %s.' % (txt, addr, domain))
            response.answer.append(dns.rrset.from_rdata(
                question.name,
                0,
                dns.rdtypes.ANY.TXT.TXT(
                    question.rdclass, question.rdtype, [txt.encode('ascii')])))
            self.tokens.set_status(uri, 'requested')
        return response.to_wire()

    def __call__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(self.address)
        except OSError as e:
            fatal(str(e))
        s.listen(1)
        while 1:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024)
                reply = self.handle_request(addr, data)
                if reply is not None:
                    conn.send(reply)


def start_servers(challenges, tokens):
    if any(x.startswith('http') for x in challenges):
        address = ('localhost', 8080)
        server = http.server.HTTPServer(address, HTTPRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        click.echo("Starting http server on %s:%s" % address)
        thread.start()
        time.sleep(0.1)
        if not thread.is_alive():
            fatal("Failed to start HTTP server on port 8080.")
        server.tokens = tokens
    if any(x.startswith('dns') for x in challenges):
        dnsaddress = ('localhost', 8053)
        dnsserver = DNSServer(dnsaddress)
        dnsthread = threading.Thread(target=dnsserver, daemon=True)
        click.echo("Starting dns server on %s:%s" % dnsaddress)
        dnsthread.start()
        time.sleep(0.1)
        if not dnsthread.is_alive():
            fatal("Failed to start DNS server on port 8053.")
        dnsserver.tokens = tokens
