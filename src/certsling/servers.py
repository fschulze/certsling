from .utils import fatal
import click
import dns.message
import dns.rdtypes.ANY.TXT
import dns.rrset
import http.server
import socket
import threading
import time


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
        self.wfile.write(self.server.tokens[token])


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
            txt = self.tokens[domain]
            print('Answering with "%s" to %s for domain %s.' % (txt, addr, domain))
            response.answer.append(dns.rrset.from_rdata(
                question.name,
                0,
                dns.rdtypes.ANY.TXT.TXT(
                    question.rdclass, question.rdtype, [txt.encode('ascii')])))
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


def start_servers(tokens):
    address = ('localhost', 8080)
    server = http.server.HTTPServer(address, HTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    click.echo("Starting http server on %s:%s" % address)
    thread.start()
    time.sleep(0.1)
    dnsaddress = ('localhost', 8053)
    dnsserver = DNSServer(dnsaddress)
    dnsthread = threading.Thread(target=dnsserver, daemon=True)
    click.echo("Starting dns server on %s:%s" % dnsaddress)
    dnsthread.start()
    time.sleep(0.1)
    if not thread.is_alive() or not dnsthread.is_alive():
        fatal("Failed to start servers.")
    dnsserver.tokens = server.tokens = tokens
