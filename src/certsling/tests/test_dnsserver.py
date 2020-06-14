def test_dns():
    from certsling.servers import DNSServer
    from certsling.servers import Tokens
    import dns.name
    request = b'\xed:\x00\x10\x00\x01\x00\x00\x00\x00\x00\x01\x0f_acMe-cHaLlenge\tLOcaLHOSt\x07ExaMPle\x03com\x00\x00\x10\x00\x01\x00\x00)\x10\x00\x00\x00\x80\x00\x00\x00'
    server = DNSServer(('127.0.0.1', 8053))
    server.tokens = Tokens()
    server.tokens[dns.name.from_text('localhost.example.com')] = ('uri', 'foo')
    reply = server.handle_request('192.168.1.42', request)
    assert reply == b'\xed:\x80\x00\x00\x01\x00\x01\x00\x00\x00\x01\x0f_acMe-cHaLlenge\tLOcaLHOSt\x07ExaMPle\x03com\x00\x00\x10\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x00\x00\x04\x03foo\x00\x00) \x00\x00\x00\x00\x00\x00\x00'
