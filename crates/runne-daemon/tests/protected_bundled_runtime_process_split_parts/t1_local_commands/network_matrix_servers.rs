use std::{
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket},
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub(super) struct Endpoints {
    pub(super) dns: SocketAddrV4,
    pub(super) http_a: SocketAddrV4,
    pub(super) http_b: SocketAddrV4,
    pub(super) read_timeout: SocketAddrV4,
    pub(super) closed: SocketAddrV4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HttpObservation {
    request_line: String,
    host: String,
    destination: SocketAddrV4,
}

impl HttpObservation {
    pub(super) fn new(
        request_line: impl Into<String>,
        host: impl Into<String>,
        destination: SocketAddrV4,
    ) -> Self {
        Self {
            request_line: request_line.into(),
            host: host.into(),
            destination,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct NetworkSnapshot {
    pub(super) dns_queries: Vec<Vec<u8>>,
    pub(super) dns_answers: Vec<Vec<u8>>,
    pub(super) http_a: Vec<HttpObservation>,
    pub(super) http_b: Vec<HttpObservation>,
    pub(super) read_timeout: Vec<HttpObservation>,
    pub(super) errors: Vec<String>,
}

pub(super) struct NetworkServers {
    endpoints: Endpoints,
    observations: Arc<Mutex<NetworkSnapshot>>,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    _closed_socket: OwnedFd,
    stopped: bool,
}

impl NetworkServers {
    pub(super) fn new() -> Self {
        let dns =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind controlled DNS UDP fixture");
        dns.set_read_timeout(Some(Duration::from_millis(40)))
            .expect("bound DNS observer receive timeout");
        let http_b_listener = bind_loopback(Ipv4Addr::new(127, 0, 0, 2));
        let http_a_listener = bind_loopback(Ipv4Addr::LOCALHOST);
        let read_timeout_listener = bind_loopback(Ipv4Addr::LOCALHOST);
        let (closed_socket, closed) = bind_unlistening_tcp();
        let endpoints = Endpoints {
            dns: ipv4(dns.local_addr().expect("DNS fixture address")),
            http_a: ipv4(http_a_listener.local_addr().expect("HTTP A address")),
            http_b: ipv4(http_b_listener.local_addr().expect("HTTP B address")),
            read_timeout: ipv4(
                read_timeout_listener
                    .local_addr()
                    .expect("read-timeout fixture address"),
            ),
            closed,
        };
        let observations = Arc::new(Mutex::new(NetworkSnapshot::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let workers = vec![
            spawn_dns(dns, Arc::clone(&observations), Arc::clone(&stop)),
            spawn_http(
                http_a_listener,
                HttpKind::A,
                endpoints,
                Arc::clone(&observations),
                Arc::clone(&stop),
            ),
            spawn_http(
                http_b_listener,
                HttpKind::B,
                endpoints,
                Arc::clone(&observations),
                Arc::clone(&stop),
            ),
            spawn_http(
                read_timeout_listener,
                HttpKind::ReadTimeout,
                endpoints,
                Arc::clone(&observations),
                Arc::clone(&stop),
            ),
        ];
        Self {
            endpoints,
            observations,
            stop,
            workers,
            _closed_socket: closed_socket,
            stopped: false,
        }
    }

    pub(super) fn endpoints(&self) -> Endpoints {
        self.endpoints
    }

    pub(super) fn snapshot(&self) -> NetworkSnapshot {
        self.observations
            .lock()
            .expect("network fixture observation lock")
            .clone()
    }

    pub(super) fn shutdown(&mut self) {
        if self.stopped {
            return;
        }
        self.stop.store(true, Ordering::Release);
        let mut worker_panicked = false;
        for worker in self.workers.drain(..) {
            worker_panicked |= worker.join().is_err();
        }
        assert!(
            !worker_panicked || thread::panicking(),
            "network fixture worker panicked during explicit shutdown"
        );
        self.stopped = true;
    }
}

impl Drop for NetworkServers {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn ipv4(address: SocketAddr) -> SocketAddrV4 {
    match address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => panic!("fixture listener unexpectedly bound IPv6"),
    }
}

fn bind_loopback(address: Ipv4Addr) -> TcpListener {
    let listener = TcpListener::bind(SocketAddrV4::new(address, 0))
        .expect("bind controlled loopback HTTP fixture");
    listener
        .set_nonblocking(true)
        .expect("make loopback HTTP fixture accept bounded");
    listener
}

pub(super) fn bind_unlistening_tcp() -> (OwnedFd, SocketAddrV4) {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(
        raw >= 0,
        "create held closed TCP endpoint: {}",
        std::io::Error::last_os_error()
    );
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_family = libc::AF_INET as libc::sa_family_t;
    address.sin_port = 0;
    address.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()),
    };
    let bind_result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert_eq!(
        bind_result,
        0,
        "bind held non-listening TCP endpoint: {}",
        std::io::Error::last_os_error()
    );
    let mut actual: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut actual_length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let name_result = unsafe {
        libc::getsockname(
            socket.as_raw_fd(),
            (&mut actual as *mut libc::sockaddr_in).cast(),
            &mut actual_length,
        )
    };
    assert_eq!(
        name_result,
        0,
        "read held TCP endpoint address: {}",
        std::io::Error::last_os_error()
    );
    (
        socket,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, u16::from_be(actual.sin_port)),
    )
}

fn spawn_dns(
    socket: UdpSocket,
    observations: Arc<Mutex<NetworkSnapshot>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("permission-mode-dns-fixture".to_owned())
        .spawn(move || {
            let mut buffer = [0_u8; 512];
            let mut answer_number = 0_usize;
            while !stop.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer) {
                    Ok((size, peer)) => {
                        let query = buffer[..size].to_vec();
                        let address = if answer_number == 0 {
                            Ipv4Addr::LOCALHOST
                        } else {
                            Ipv4Addr::new(127, 0, 0, 2)
                        };
                        answer_number += 1;
                        let answer = dns_answer(&query, address);
                        match answer {
                            Some(answer) => {
                                {
                                    let mut snapshot = observations
                                        .lock()
                                        .expect("network fixture observation lock");
                                    snapshot.dns_queries.push(query);
                                    snapshot.dns_answers.push(answer.clone());
                                }
                                if let Err(error) = socket.send_to(&answer, peer) {
                                    record_error(
                                        &observations,
                                        format!("send controlled DNS reply: {error}"),
                                    );
                                }
                            }
                            None => {
                                let mut snapshot = observations
                                    .lock()
                                    .expect("network fixture observation lock");
                                snapshot.dns_queries.push(query);
                                snapshot
                                    .errors
                                    .push("malformed controlled DNS query".to_owned());
                            }
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => record_error(
                        &observations,
                        format!("receive controlled DNS query: {error}"),
                    ),
                }
            }
        })
        .expect("start bounded DNS fixture observer")
}

fn dns_answer(query: &[u8], address: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 17 || query[4..6] != [0, 1] {
        return None;
    }
    let mut question_end = 12;
    loop {
        let label_size = usize::from(*query.get(question_end)?);
        question_end += 1;
        if label_size == 0 {
            break;
        }
        question_end = question_end.checked_add(label_size)?;
        if question_end >= query.len() {
            return None;
        }
    }
    question_end = question_end.checked_add(4)?;
    if question_end != query.len() {
        return None;
    }
    let mut answer = Vec::with_capacity(query.len() + 16);
    answer.extend_from_slice(&query[..2]);
    answer.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    answer.extend_from_slice(&query[12..question_end]);
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
    answer.extend_from_slice(&address.octets());
    Some(answer)
}

#[derive(Clone, Copy)]
enum HttpKind {
    A,
    B,
    ReadTimeout,
}

fn spawn_http(
    listener: TcpListener,
    kind: HttpKind,
    endpoints: Endpoints,
    observations: Arc<Mutex<NetworkSnapshot>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    let thread_name = match kind {
        HttpKind::A => "permission-mode-http-a",
        HttpKind::B => "permission-mode-http-b",
        HttpKind::ReadTimeout => "permission-mode-http-read-timeout",
    };
    thread::Builder::new()
        .name(thread_name.to_owned())
        .spawn(move || {
            let mut held_streams = Vec::<TcpStream>::new();
            while !stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                        let request = read_request(&mut stream, &stop);
                        let (request_line, host) = match request {
                            Ok(request) => request,
                            Err(error) => {
                                record_error(&observations, error);
                                continue;
                            }
                        };
                        let destination = match stream.local_addr() {
                            Ok(address) => ipv4(address),
                            Err(error) => {
                                record_error(
                                    &observations,
                                    format!("read HTTP fixture destination: {error}"),
                                );
                                continue;
                            }
                        };
                        let observation = HttpObservation::new(request_line, host, destination);
                        {
                            let mut snapshot = observations
                                .lock()
                                .expect("network fixture observation lock");
                            match kind {
                                HttpKind::A => snapshot.http_a.push(observation),
                                HttpKind::B => snapshot.http_b.push(observation),
                                HttpKind::ReadTimeout => snapshot.read_timeout.push(observation),
                            }
                        }
                        match kind {
                            HttpKind::A => {
                                let location = format!(
                                    "http://{}/rebound",
                                    endpoints.http_b
                                );
                                let response = format!(
                                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                );
                                if let Err(error) = stream.write_all(response.as_bytes()) {
                                    record_error(
                                        &observations,
                                        format!("write controlled HTTP redirect: {error}"),
                                    );
                                }
                            }
                            HttpKind::B => {
                                let body = b"network-matrix-ok";
                                let header = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                if let Err(error) = stream
                                    .write_all(header.as_bytes())
                                    .and_then(|()| stream.write_all(body))
                                {
                                    record_error(
                                        &observations,
                                        format!("write controlled HTTP B response: {error}"),
                                    );
                                }
                            }
                            HttpKind::ReadTimeout => {
                                held_streams.push(stream);
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => record_error(
                        &observations,
                        format!("accept controlled HTTP request: {error}"),
                    ),
                }
            }
            for stream in held_streams {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        })
        .expect("start bounded HTTP fixture observer")
}

fn read_request(stream: &mut TcpStream, stop: &AtomicBool) -> Result<(String, String), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    loop {
        if stop.load(Ordering::Acquire) {
            return Err("HTTP fixture stopped before request completed".to_owned());
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Err("HTTP peer closed before complete request headers".to_owned()),
            Ok(size) => {
                bytes.extend_from_slice(&buffer[..size]);
                if bytes.len() > 16 * 1024 {
                    return Err("HTTP fixture request headers exceeded 16 KiB".to_owned());
                }
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    let text = String::from_utf8_lossy(&bytes);
                    let mut lines = text.split("\r\n");
                    let request_line = lines
                        .next()
                        .ok_or_else(|| "HTTP request line missing".to_owned())?
                        .to_owned();
                    let host = lines
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
                                .map(|(_, value)| value.trim().to_owned())
                        })
                        .ok_or_else(|| "HTTP Host header missing".to_owned())?;
                    return Ok((request_line, host));
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err("HTTP fixture request-header read timed out".to_owned());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("read HTTP fixture request: {error}")),
        }
    }
}

fn record_error(observations: &Mutex<NetworkSnapshot>, error: String) {
    observations
        .lock()
        .expect("network fixture observation lock")
        .errors
        .push(error);
}
