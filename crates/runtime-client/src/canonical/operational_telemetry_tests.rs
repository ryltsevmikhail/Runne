#[tokio::test]
async fn bounded_telemetry_read_uses_fixed_capacity_for_fragmented_maximum() {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let first = vec![b'a'; 40_000];
    let second = vec![b'b'; gocode_api::MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1 - first.len()];
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 1024]; let _ = stream.readable().await; let _ = stream.try_read(&mut request);
        let mut wire = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
        for chunk in [&first, &second] { wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes()); wire.extend_from_slice(chunk); wire.extend_from_slice(b"\r\n"); }
        wire.extend_from_slice(b"0\r\n\r\n"); stream.write_all(&wire).await.unwrap();
    });
    let response = reqwest::Client::new().get(format!("http://{address}")).send().await.unwrap();
    let body = read_operational_telemetry_bounded(response).await.unwrap();
    assert_eq!(body.len(), gocode_api::MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1);
    assert_eq!(body.capacity(), gocode_api::MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1);
}
