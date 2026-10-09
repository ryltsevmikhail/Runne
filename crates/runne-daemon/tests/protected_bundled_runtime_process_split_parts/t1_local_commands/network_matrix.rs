use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

#[path = "network_matrix_servers.rs"]
mod servers;

pub(super) fn bind_unlistening_tcp() -> (OwnedFd, SocketAddrV4) {
    servers::bind_unlistening_tcp()
}

const QUERY_ONE_ID: u16 = 0x51a1;
const QUERY_TWO_ID: u16 = 0x51a2;
const QNAME_WIRE: &[u8] = b"\x07fixture\x04test\x00";
const RESPONSE_BODY: &str = "network-matrix-ok";

pub(super) struct NetworkMatrix {
    broad: bool,
    marker: String,
    script_path: PathBuf,
    result_path: PathBuf,
    append_path: PathBuf,
    stderr_path: PathBuf,
    endpoints: servers::Endpoints,
    servers: servers::NetworkServers,
}

impl NetworkMatrix {
    pub(super) fn new(project_directory: &Path, marker: &str, broad: bool) -> Self {
        let servers = servers::NetworkServers::new();
        let endpoints = servers.endpoints();
        let script_path = project_directory.join(format!("{marker}-network-matrix.py"));
        let result_path = project_directory.join(format!("{marker}-network-results.jsonl"));
        let append_path = project_directory.join(format!("{marker}-network-append-marker"));
        let stderr_path = project_directory.join(format!("{marker}-network-stderr.txt"));
        std::fs::write(&script_path, PYTHON_NETWORK_MATRIX)
            .expect("write fixture-owned network child script");
        std::fs::write(&result_path, "").expect("prepare network result file");
        std::fs::write(&append_path, "").expect("prepare network append marker");
        std::fs::write(&stderr_path, "").expect("prepare network diagnostic file");
        Self {
            broad,
            marker: marker.to_owned(),
            script_path,
            result_path,
            append_path,
            stderr_path,
            endpoints,
            servers,
        }
    }

    pub(super) fn shell_script(&self) -> String {
        format!(
            "python3 {} {} {} {} {} {} {} {} {} {} 2> {}",
            shell_quote(&self.script_path),
            if self.broad { "broad" } else { "none" },
            self.endpoints.dns.port(),
            self.endpoints.http_a.port(),
            self.endpoints.http_b.port(),
            self.endpoints.read_timeout.port(),
            self.endpoints.closed.port(),
            shell_quote(&self.result_path),
            shell_quote(&self.append_path),
            shell_quote(Path::new(&self.marker)),
            shell_quote(&self.stderr_path),
        )
    }

    pub(super) fn assert_pending(&self) {
        for path in [&self.result_path, &self.append_path, &self.stderr_path] {
            assert!(
                std::fs::read(path)
                    .expect("read pending network fixture file")
                    .is_empty()
            );
        }
        let observed = self.servers.snapshot();
        assert!(observed.dns_queries.is_empty());
        assert!(observed.dns_answers.is_empty());
        assert!(observed.http_a.is_empty());
        assert!(observed.http_b.is_empty());
        assert!(observed.read_timeout.is_empty());
        assert!(observed.errors.is_empty());
    }

    pub(super) fn assert_records(&self) {
        let stderr = std::fs::read_to_string(&self.stderr_path)
            .expect("read fixture-owned network child diagnostic file");
        eprintln!("INFO: network-matrix child stderr: {stderr:?}");
        assert!(
            stderr.is_empty(),
            "network-matrix child wrote stderr diagnostic:\n{stderr}"
        );
        let result_bytes = std::fs::read(&self.result_path).expect("read network result record");
        let lines = result_bytes
            .split(|byte| *byte == b'\n')
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "child appends exactly one JSON result line");
        assert!(!lines[0].is_empty(), "network result line is present");
        let result: serde_json::Value =
            serde_json::from_slice(lines[0]).expect("parse exact network semantic result");
        assert_eq!(
            std::fs::read(&self.append_path).expect("read one child append marker"),
            format!("{}\n", self.marker).as_bytes(),
            "child appends its network marker exactly once"
        );
        assert_eq!(result["marker"], self.marker);
        assert_eq!(result["automatic_retries"], 0);

        let observed = self.servers.snapshot();
        assert!(
            observed.errors.is_empty(),
            "controlled loopback fixture server errors: {:?}",
            observed.errors
        );
        if self.broad {
            self.assert_broad_result(&result, &observed);
        } else {
            self.assert_network_none_result(&result, &observed);
        }
    }

    fn assert_broad_result(&self, result: &serde_json::Value, observed: &servers::NetworkSnapshot) {
        let endpoints = self.servers.endpoints();
        assert_eq!(result["mode"], "broad");
        assert_eq!(
            result["dns"],
            serde_json::json!([
                {"id": QUERY_ONE_ID, "question": "fixture.test A", "answer": "127.0.0.1", "ttl": 0},
                {"id": QUERY_TWO_ID, "question": "fixture.test A", "answer": "127.0.0.2", "ttl": 0}
            ])
        );
        assert_eq!(
            result["http"],
            serde_json::json!([
                {"path": "/redirect", "destination": endpoints.http_a.to_string(), "status": 302},
                {"path": "/rebound", "destination": endpoints.http_b.to_string(), "status": 200, "body": RESPONSE_BODY}
            ])
        );
        assert_eq!(result["closed_endpoint"], "ECONNREFUSED");
        assert_eq!(result["read_timeout"], "bounded_read_timeout");

        let query_one = dns_query(QUERY_ONE_ID);
        let query_two = dns_query(QUERY_TWO_ID);
        assert_eq!(
            observed.dns_queries,
            vec![query_one.clone(), query_two.clone()]
        );
        assert_eq!(
            observed.dns_answers,
            vec![
                dns_answer(&query_one, Ipv4Addr::LOCALHOST),
                dns_answer(&query_two, Ipv4Addr::new(127, 0, 0, 2)),
            ],
            "fixture returned exact query IDs, question bytes, A records, and TTL zero"
        );
        assert_eq!(
            observed.http_a,
            vec![servers::HttpObservation::new(
                "GET /redirect HTTP/1.1",
                format!("{}:{}", Ipv4Addr::LOCALHOST, endpoints.http_a.port()),
                endpoints.http_a,
            )]
        );
        assert_eq!(
            observed.http_b,
            vec![servers::HttpObservation::new(
                "GET /rebound HTTP/1.1",
                format!(
                    "{}:{}",
                    Ipv4Addr::new(127, 0, 0, 2),
                    endpoints.http_b.port()
                ),
                endpoints.http_b,
            )]
        );
        assert_eq!(
            observed.read_timeout,
            vec![servers::HttpObservation::new(
                "GET /hold HTTP/1.1",
                format!("{}:{}", Ipv4Addr::LOCALHOST, endpoints.read_timeout.port()),
                endpoints.read_timeout,
            )]
        );
    }

    fn assert_network_none_result(
        &self,
        result: &serde_json::Value,
        observed: &servers::NetworkSnapshot,
    ) {
        assert_eq!(result["mode"], "network_none");
        assert!(matches!(
            result["udp_denial"].as_str(),
            Some("socket:EPERM" | "sendto:EPERM")
        ));
        assert!(matches!(
            result["tcp_denial"].as_str(),
            Some("socket:EPERM" | "connect:EPERM")
        ));
        assert_eq!(result["http_requests"], 0);
        assert!(
            observed.dns_queries.is_empty(),
            "Network None sent no UDP packet"
        );
        assert!(observed.dns_answers.is_empty());
        assert!(
            observed.http_a.is_empty(),
            "Network None sent no HTTP request to A"
        );
        assert!(
            observed.http_b.is_empty(),
            "Network None sent no HTTP request to B"
        );
        assert!(
            observed.read_timeout.is_empty(),
            "Network None sent no HTTP read-timeout request"
        );
    }

    pub(super) fn shutdown(&mut self) {
        self.servers.shutdown();
    }
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn dns_query(query_id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12 + QNAME_WIRE.len() + 4);
    packet.extend_from_slice(&query_id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(QNAME_WIRE);
    packet.extend_from_slice(&[0, 1, 0, 1]);
    packet
}

fn dns_answer(query: &[u8], address: Ipv4Addr) -> Vec<u8> {
    let mut packet = Vec::with_capacity(query.len() + 16);
    packet.extend_from_slice(&query[..2]);
    packet.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    packet.extend_from_slice(&query[12..]);
    packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
    packet.extend_from_slice(&address.octets());
    packet
}

const PYTHON_NETWORK_MATRIX: &str = r#"import errno, http.client, json, socket, struct, sys, urllib.parse

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
