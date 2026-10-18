use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket},
    os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[path = "network_matrix_servers/dns.rs"]
mod dns;
#[path = "network_matrix_servers/http.rs"]
mod http;

use dns::spawn_dns;
use http::{HttpKind, spawn_http};

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
