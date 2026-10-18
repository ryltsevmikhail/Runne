pub(super) const PYTHON_NETWORK_MATRIX: &str = r#"import errno, http.client, json, socket, struct, sys, urllib.parse

mode, dns_port, a_port, b_port, timeout_port, closed_port, result_path, append_path, marker = sys.argv[1:]
dns_port, a_port, b_port, timeout_port, closed_port = map(int, (dns_port, a_port, b_port, timeout_port, closed_port))
qname = b'\x07fixture\x04test\x00'

def query(query_id, expected_ip):
    question = qname + b'\x00\x01\x00\x01'
    packet = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0) + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.sendto(packet, ('127.0.0.1', dns_port))
    reply, peer = sock.recvfrom(512)
    sock.close()
    answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04' + socket.inet_aton(expected_ip)
    expected = struct.pack('!HHHHHH', query_id, 0x8180, 1, 1, 0, 0) + question + answer
    if reply != expected or peer[0] != '127.0.0.1':
        raise AssertionError('controlled DNS reply bytes or source did not match')
    return expected_ip

result = {'mode': 'broad' if mode == 'broad' else 'network_none', 'marker': marker, 'automatic_retries': 0}
if mode == 'broad':
    first_ip = query(0x51a1, '127.0.0.1')
    first = http.client.HTTPConnection(first_ip, a_port, timeout=1.0)
    first.request('GET', '/redirect')
    response = first.getresponse()
    location = response.getheader('Location')
    response.read()
    first.close()
    expected_location = 'http://127.0.0.2:%d/rebound' % b_port
    parsed_location = urllib.parse.urlsplit(location or '')
    if response.status != 302 or location != expected_location:
        raise AssertionError('A did not return the exact local-only B redirect')

    second_ip = query(0x51a2, '127.0.0.2')
    if (second_ip != '127.0.0.2' or parsed_location.scheme != 'http'
            or parsed_location.hostname != second_ip or parsed_location.port != b_port
            or parsed_location.path != '/rebound'):
        raise AssertionError('the second fixture.test A answer did not change')
    second = http.client.HTTPConnection(parsed_location.hostname, parsed_location.port, timeout=1.0)
    second.request('GET', parsed_location.path)
    response_b = second.getresponse()
    body = response_b.read().decode('ascii')
    second.close()
    if response_b.status != 200 or body != 'network-matrix-ok':
        raise AssertionError('direct local B request did not return its fixture body')
    result['dns'] = [
        {'id': 0x51a1, 'question': 'fixture.test A', 'answer': first_ip, 'ttl': 0},
        {'id': 0x51a2, 'question': 'fixture.test A', 'answer': second_ip, 'ttl': 0},
    ]
    result['http'] = [
        {'path': '/redirect', 'destination': '127.0.0.1:%d' % a_port, 'status': 302},
        {'path': '/rebound', 'destination': '127.0.0.2:%d' % b_port, 'status': 200, 'body': body},
    ]

    closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        closed.connect(('127.0.0.1', closed_port))
    except OSError as error:
        if error.errno != errno.ECONNREFUSED:
            raise
        result['closed_endpoint'] = 'ECONNREFUSED'
    else:
        raise AssertionError('bound non-listening loopback endpoint accepted TCP')
    finally:
        closed.close()

    stalled = http.client.HTTPConnection('127.0.0.1', timeout_port, timeout=0.25)
    stalled.request('GET', '/hold')
    try:
        stalled.getresponse()
    except socket.timeout:
        result['read_timeout'] = 'bounded_read_timeout'
    else:
        raise AssertionError('held loopback response did not time out')
    finally:
        stalled.close()
else:
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
        result['udp_denial'] = 'socket:EPERM'
    else:
        try:
            try:
                probe.sendto(b'\x51\xa1\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07fixture\x04test\x00\x00\x01\x00\x01', ('127.0.0.1', dns_port))
            except OSError as error:
                if error.errno != errno.EPERM:
                    raise
                result['udp_denial'] = 'sendto:EPERM'
            else:
                raise AssertionError('Network None delivered a UDP DNS query')
        finally:
            probe.close()
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
        result['tcp_denial'] = 'socket:EPERM'
    else:
        try:
            tcp.connect(('127.0.0.1', a_port))
        except OSError as error:
            if error.errno != errno.EPERM:
                raise
            result['tcp_denial'] = 'connect:EPERM'
        else:
            raise AssertionError('Network None connected to controlled HTTP A')
        finally:
            tcp.close()
    result['http_requests'] = 0

encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode('utf-8') + b'\n'
with open(result_path, 'ab') as output:
    output.write(encoded)
with open(append_path, 'ab') as output:
    output.write((marker + '\n').encode('utf-8'))
"#;
