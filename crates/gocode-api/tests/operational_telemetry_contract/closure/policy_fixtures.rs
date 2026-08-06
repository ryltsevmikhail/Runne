use std::fs;

use super::resolver;

#[test]
fn token_policy_rejects_dangerous_runtime_client_response_methods() {
    assert!(resolve_runtime_fixture("async fn read() { response.bytes().await; }").is_err());
}

#[test]
fn token_policy_accepts_audited_runtime_client_get_chain() {
    let source = r#"
        const OPERATIONAL_TELEMETRY_PATH: &str = "/v1/runtime/operational-telemetry";
        async fn read() {
            let response: reqwest::Response = self.authenticated_request(self.http_client().get(self.url(OPERATIONAL_TELEMETRY_PATH)))?.send().await;
            let _ = response.status();
            let _ = response.headers();
            while let Some(chunk) = response.chunk().await {
                let length = body.len().checked_add(chunk.len()).unwrap();
                if length > maximum { return; }
                body.extend_from_slice(&chunk);
            }
            let _: Result<(), reqwest::Error> = Ok(());
            let _ = serde_json::from_slice::<u8>(bytes);
        }
    "#;
    assert!(resolve_runtime_fixture(source).is_ok());
}

#[test]
fn token_policy_rejects_outbound_io_process_and_runtime_client_escapes() {
    for source in [
        "use std::net::TcpSocket;",
        "use std::net::TcpSocket as LoopbackSocket;",
        "use tokio::net::TcpStream;",
        "use tokio::io::AsyncWriteExt;",
        "stream.write_all(bytes).await; stream.flush().await; stream.shutdown().await;",
        "stream.writable().await; stream.write(bytes); stream.try_write(bytes); stream.try_write_vectored(vectors);",
        "stream.poll_write(cx, bytes); stream.poll_write_vectored(cx, vectors); stream.write_buf(buffer);",
        "stream.send(bytes); stream.send_to(bytes, address); stream.try_send_to(bytes, address); stream.poll_send(cx, bytes); stream.start_send(bytes);",
        "stop.send(()); runtime_controller.shutdown(ShutdownMode::Immediate { timeout }); controller.shutdown(ShutdownMode::Graceful { timeout });",
        "std::fs::write(path, bytes); std::io::stdin(); std::io::stdout(); std::io::stderr();",
        "use std::fs::{File, OpenOptions}; use std::process::{Command, Stdio};",
        "use tokio::process::Command; use std::io::{BufReader, BufWriter};",
        "let client: reqwest::Client = reqwest::Client::new();",
        "unsafe { libc::write(fd, bytes, length); }",
        "use libc as c; unsafe { c::socket(domain, kind, protocol); c::connect(fd, address, length); c::send(fd, bytes, length, flags); }",
        "extern \"C\" { fn write(fd: i32); }",
        "unsafe extern \"C\" { fn telemetry_ffi(); }",
        "extern crate libc; unsafe fn raw_ffi() {}",
    ] {
        assert!(resolve_fixture(source).is_err(), "{source}");
    }
    for source in [
        "self.authenticated_request(self.http_client().post(self.url(OPERATIONAL_TELEMETRY_PATH)))?.send().await;",
        "self.http_client().put(self.url(OPERATIONAL_TELEMETRY_PATH)); self.http_client().patch(self.url(OPERATIONAL_TELEMETRY_PATH));",
        "self.http_client().delete(self.url(OPERATIONAL_TELEMETRY_PATH)); self.http_client().head(self.url(OPERATIONAL_TELEMETRY_PATH));",
        "self.http_client().request(method, self.url(OPERATIONAL_TELEMETRY_PATH)); self.http_client().build();",
        "self.authenticated_request(self.http_client().get(self.url(SECOND_PATH)))?.send().await;",
        "self.authenticated_request(self.http_client().get(self.url(OPERATIONAL_TELEMETRY_PATH)))?.execute().await;",
        "self.http_client().connect(self.url(OPERATIONAL_TELEMETRY_PATH)); response.bytes().await; response.text().await; response.json().await;",
    ] {
        assert!(resolve_runtime_fixture(source).is_err(), "{source}");
    }
    for (path, source) in [
        (
            "crates/gocode-http/src/secure_local_host.rs",
            "use tokio::net::TcpListener as Listener;",
        ),
        (
            "crates/gocode-http/src/secure_local_host.rs",
            "use std::net::SocketAddr as Address;",
        ),
        (
            "crates/gocode-http/src/secure_local_host.rs",
            "use hyper_util as transport;",
        ),
        (
            "crates/gocode-runtime/src/provider_execution_parts/part_01.rs",
            "use core::fmt::{self, Write as Formatting};",
        ),
    ] {
        assert!(
            resolve_path_fixture(path, source).is_err(),
            "{path}: {source}"
        );
    }
}

#[test]
fn token_policy_ignores_ffi_words_in_literals_and_comments() {
    let source = r#"
        // unsafe { libc::write(fd, bytes, length); } extern "C" { fn write(); }
        const MESSAGE: &str = "libc::socket unsafe extern crate";
    "#;
    assert!(resolve_fixture(source).is_ok());
}

#[test]
fn token_policy_accepts_exact_io_exceptions() {
    for (path, source) in [
        (
            "crates/gocode-http/src/secure_local_host.rs",
            "use std::net::SocketAddr; use hyper::service::service_fn; use hyper_util::rt::TokioIo; use tokio_rustls::TlsAcceptor; use tokio::net::TcpListener;",
        ),
        (
            "crates/gocode-http/src/secure_local_host/operational_telemetry.rs",
            "use tokio::net::TcpListener;",
        ),
        (
            "crates/gocode-runtime/src/provider_execution_parts/part_01.rs",
            "use core::fmt::{self, Write as _};",
        ),
        (
            "crates/app-core/src/lib_parts/operational_telemetry_state.rs",
            "self.host_lifecycle.write();",
        ),
        (
            "crates/gocode-http/src/secure_local_host.rs",
            "stop.send(());",
        ),
        (
            "crates/gocode-daemon/src/application/http_startup.rs",
            "runtime_controller.shutdown(ShutdownMode::Immediate { timeout });",
        ),
        (
            "crates/gocode-daemon/src/application/shutdown.rs",
            "controller.shutdown(ShutdownMode::Graceful { timeout });",
        ),
        (
            "src/runtime.rs",
            "use std::path::{Path, PathBuf}; formatter.write_str(value); sender.try_send(value); tokio::runtime::Builder::new_current_thread().build();",
        ),
    ] {
        assert!(resolve_path_fixture(path, source).is_ok(), "{path}");
    }
}

fn resolve_fixture(source: &str) -> Result<std::collections::BTreeSet<String>, String> {
    resolve_path_fixture("src/root.rs", source)
}

fn resolve_runtime_fixture(source: &str) -> Result<std::collections::BTreeSet<String>, String> {
    resolve_path_fixture(
        "crates/runtime-client/src/canonical/operational_telemetry.rs",
        source,
    )
}

fn resolve_path_fixture(
    path: &str,
    source: &str,
) -> Result<std::collections::BTreeSet<String>, String> {
    let workspace = tempfile::tempdir().unwrap();
    let source_path = workspace.path().join(path);
    fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    fs::write(source_path, source).unwrap();
    resolver::resolve_closure(workspace.path(), &[path])
}
