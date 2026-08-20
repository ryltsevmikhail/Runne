use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use runne_api::{
    ApiPrincipalId, ApiReplayAggregateKind, DaemonInstanceId, ReplayRetentionBaselineWireV1,
    RuntimeSessionBinding, StableRuntimeBinding, UnauthenticatedReplayRetentionBaselineFieldsV1,
};
use runne_runtime_client::{
    CanonicalId, ReplayAggregateKind, ReplayClientError, ReplayClientErrorKind, ReplayScope,
    RuntimeSessionInfo, mock_authenticated_runtime_client,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

type HmacSha256 = Hmac<Sha256>;

const AUTHORITY: [u8; 32] = [0x5a; 32];
pub const AGGREGATE: &str = "018f2e3a-7000-7000-8000-000000000110";
pub const REQUEST_ID: &str = "018f2e3a-7000-7000-8000-000000000120";

pub fn scope() -> ReplayScope {
    ReplayScope::new(
        ReplayAggregateKind::Conversation,
        CanonicalId::parse(AGGREGATE).unwrap(),
    )
}

fn session() -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".to_owned(),
        schema_hash: hex::encode([3; 32]),
        runtime_version: "test".to_owned(),
        capabilities: vec!["test".to_owned()],
        authority_id: "018f2e3a-7000-7000-8000-000000000101".to_owned(),
        principal_id: "local-owner".to_owned(),
        event_log_lineage_id: "018f2e3a-7000-7000-8000-000000000102".to_owned(),
        daemon_instance_id: "018f2e3a-7000-7000-8000-000000000103".to_owned(),
        launch_generation: 7,
        session_id: "018f2e3a700070008000000000000104".to_owned(),
        authorization_epoch: 0,
        sensitivity_ceiling: "sensitive".to_owned(),
        certificate_sha256: hex::encode([6; 32]),
        capability_digest: hex::encode([4; 32]),
    }
}

fn binding() -> RuntimeSessionBinding {
    let info = session();
    RuntimeSessionBinding::new_with_sensitivity_label(
        StableRuntimeBinding::new(
            uuid::Uuid::parse_str(&info.authority_id)
                .unwrap()
                .into_bytes(),
            ApiPrincipalId::new(info.principal_id).unwrap(),
            info.event_log_lineage_id.parse().unwrap(),
            info.profile_id,
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes(
            uuid::Uuid::parse_str(&info.daemon_instance_id)
                .unwrap()
                .into_bytes(),
        ),
        info.launch_generation,
        hex::decode(info.session_id).unwrap().try_into().unwrap(),
        info.authorization_epoch,
        "sensitive",
        [6; 32],
    )
    .unwrap()
}

fn projection_bytes() -> Vec<u8> {
    let id = uuid::Uuid::parse_str(AGGREGATE).unwrap().into_bytes();
    let workspace = uuid::Uuid::parse_str("018f2e3a-7000-7000-8000-000000000111")
        .unwrap()
        .into_bytes();
    [
        vec![1],
        id.to_vec(),
        workspace.to_vec(),
        vec![1, 0, 0, 0, 0, 0],
    ]
    .concat()
}

fn projection_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"gocode.replay.aggregate-projection");
    hash.update([0, 1, 2]);
    hash.update(uuid::Uuid::parse_str(AGGREGATE).unwrap().as_bytes());
    hash.update(u64::try_from(bytes.len()).unwrap().to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

fn signed_wire() -> ReplayRetentionBaselineWireV1 {
    let binding = binding();
    let aggregate_id = uuid::Uuid::parse_str(AGGREGATE).unwrap().into_bytes();
    let projection_bytes = projection_bytes();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let issued_at_unix_ms = u64::try_from(now.as_millis()).unwrap();
    let mut fields = UnauthenticatedReplayRetentionBaselineFieldsV1 {
        schema_version: 1,
        authority_id: *binding.stable().authority_id(),
        principal_id: binding.stable().principal_id().as_str().to_owned(),
        lineage_id: *binding.stable().lineage_id().as_bytes(),
        runtime_session_binding_digest: binding.canonical_digest(),
        replay_scope_digest: runne_api::canonical_aggregate_replay_scope_digest(
            ApiReplayAggregateKind::Conversation,
            &aggregate_id,
        ),
        aggregate_kind: ApiReplayAggregateKind::Conversation,
        aggregate_id,
        sequence: 1,
        version: 1,
        baseline_global_position: 1,
        projection_codec: 1,
        projection_digest: projection_digest(&projection_bytes),
        projection_bytes,
        retained_floor: 2,
        captured_high_water: 2,
        retention_generation: 1,
        retention_witness: [8; 32],
        issued_at_unix_ms,
        expires_at_unix_ms: issued_at_unix_ms.saturating_add(30_000),
        witness_mac: [0; 32],
    };
    let unsigned = ReplayRetentionBaselineWireV1::from_unauthenticated_fields(fields.clone());
    let mut derive = HmacSha256::new_from_slice(&AUTHORITY).unwrap();
    derive.update(runne_api::REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V1);
    derive.update(&fields.runtime_session_binding_digest);
    let key = derive.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(&runne_api::replay_retention_baseline_transcript(&unsigned));
    fields.witness_mac = mac.finalize().into_bytes().into();
    ReplayRetentionBaselineWireV1::from_unauthenticated_fields(fields)
}

pub fn valid_body() -> Value {
    let f = signed_wire().to_unauthenticated_fields();
    json!({"code":"replay_retention_gap","requestId":REQUEST_ID,"baseline":{
        "schemaVersion":f.schema_version,"authorityId":hex::encode(f.authority_id),"principalId":f.principal_id,
        "lineageId":hex::encode(f.lineage_id),"runtimeSessionBindingDigest":hex::encode(f.runtime_session_binding_digest),
        "replayScopeDigest":hex::encode(f.replay_scope_digest),"aggregateKind":"conversation","aggregateId":hex::encode(f.aggregate_id),
        "sequence":f.sequence,"version":f.version,"baselineGlobalPosition":f.baseline_global_position,
        "projectionCodec":f.projection_codec,"projectionBytes":URL_SAFE_NO_PAD.encode(f.projection_bytes),
        "projectionDigest":hex::encode(f.projection_digest),"retainedFloor":f.retained_floor,
        "capturedHighWater":f.captured_high_water,"retentionGeneration":f.retention_generation,
        "retentionWitness":hex::encode(f.retention_witness),"issuedAtUnixMs":f.issued_at_unix_ms,
        "expiresAtUnixMs":f.expires_at_unix_ms,"witnessMac":hex::encode(f.witness_mac)}})
}

pub async fn one_response(raw: String) -> ReplayClientError {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let read = stream.read(&mut request).await.unwrap();
        assert!(
            std::str::from_utf8(&request[..read])
                .unwrap()
                .starts_with("POST /v1/replay/open-session")
        );
        stream.write_all(raw.as_bytes()).await.unwrap();
    });
    let client =
        mock_authenticated_runtime_client(&format!("http://{address}"), session()).unwrap();
    let Err(error) = client.catch_up(scope(), None, |_| Ok::<_, ()>(())).await else {
        panic!("retention response must not enter live replay");
    };
    server.await.unwrap();
    error
}

pub fn response(body: &Value) -> String {
    let body = serde_json::to_vec(body).unwrap();
    format!(
        "HTTP/1.1 410 Gone\r\ncontent-type: application/json\r\nx-request-id: {REQUEST_ID}\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8(body).unwrap()
    )
}

pub async fn rejects(raw: String) {
    let error = one_response(raw).await;
    assert_ne!(error.kind(), ReplayClientErrorKind::RetentionGap);
    assert!(error.retention_baseline().is_none());
}
