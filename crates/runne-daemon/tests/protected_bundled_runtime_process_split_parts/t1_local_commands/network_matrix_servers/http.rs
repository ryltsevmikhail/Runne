use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use super::{Endpoints, HttpObservation, NetworkSnapshot, ipv4};

#[derive(Clone, Copy)]
pub(super) enum HttpKind {
    A,
    B,
    ReadTimeout,
}

pub(super) fn spawn_http(
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

pub(super) fn record_error(observations: &Mutex<NetworkSnapshot>, error: String) {
    observations
        .lock()
        .expect("network fixture observation lock")
        .errors
        .push(error);
}
