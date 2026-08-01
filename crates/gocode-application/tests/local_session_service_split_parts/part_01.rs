use std::time::Duration;

use gocode_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use gocode_application::local_session::{
    BootstrapProof, LocalSessionError, LocalSessionService, bootstrap_proof_transcript,
};
use gocode_domain::{event::Sensitivity, id::EventLogLineageId};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const AUTHORITY: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 1,
];
const DAEMON: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 2,
];
const LINEAGE: &str = "018f2e3a-7000-7000-8000-000000000003";
const CERTIFICATE: [u8; 32] = [0x11; 32];
const SECRET: [u8; 32] = [0x22; 32];

fn runtime_binding(generation: u64, epoch: u64) -> RuntimeSessionBinding {
    runtime_binding_with_session(generation, epoch, [0x55; 16])
}

fn runtime_binding_with_session(
    generation: u64,
    epoch: u64,
    session_id: [u8; 16],
) -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            AUTHORITY,
            ApiPrincipalId::new("local-owner").unwrap(),
            LINEAGE.parse::<EventLogLineageId>().unwrap(),
            "gocode-ui-client/1",
            [0x33; 32],
            [0x44; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes(DAEMON),
        generation,
        session_id,
        epoch,
        Sensitivity::Internal,
        CERTIFICATE,
    )
    .unwrap()
}

fn proof(
    binding: &RuntimeSessionBinding,
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
) -> BootstrapProof {
    proof_with_secret(binding, server_nonce, client_nonce, &SECRET)
}

fn proof_with_secret(
    binding: &RuntimeSessionBinding,
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
    secret: &[u8; 32],
) -> BootstrapProof {
    let transcript = bootstrap_proof_transcript(binding, server_nonce, client_nonce);
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(&transcript);
    BootstrapProof::new(mac.finalize().into_bytes().into())
}

#[test]
fn golden_transcript_and_correct_proof_issue_a_memory_only_authority() {
    let binding = runtime_binding(7, 3);
    let transcript = bootstrap_proof_transcript(&binding, [0x66; 32], [0x77; 32]);
    assert_eq!(
        hex::encode(&transcript),
        "676f636f64652f6c6f63616c2d72756e74696d652f626f6f7473747261702d70726f6f662f76320000000002111111111111111111111111111111111111111111111111111111111111111166666666666666666666666666666666666666666666666666666666666666667777777777777777777777777777777777777777777777777777777777777777018f2e3a700070008000000000000001000b6c6f63616c2d6f776e6572018f2e3a700070008000000000000003018f2e3a70007000800000000000000200000000000000070012676f636f64652d75692d636c69656e742f3133333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444"
    );
    let mut golden_mac = HmacSha256::new_from_slice(&SECRET).unwrap();
    golden_mac.update(&transcript);
    assert_eq!(
        hex::encode(golden_mac.finalize().into_bytes()),
        "b6ac513c2a9a5437a0038c4928c2330547a918a963891cba5d36daea2fd5b866"
    );
    let mut service = LocalSessionService::new(binding.clone(), SECRET);
    let challenge = service
        .issue_challenge([0x77; 32], [0x66; 32], Duration::from_secs(0))
        .unwrap();
    let issued = service
        .authenticate(
            challenge.id,
            proof(&binding, [0x66; 32], [0x77; 32]),
            [0x88; 32],
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(issued.binding, binding);
    assert!(
        service
            .authorize_wire(&[0x88; 32], Duration::from_secs(1))
            .is_ok()
    );
}

#[test]
fn invalid_binding_proof_replay_and_expiry_fail_closed() {
    let binding = runtime_binding(7, 3);
    let mut service = LocalSessionService::new(binding.clone(), SECRET);
    let challenge = service
        .issue_challenge([2; 32], [1; 32], Duration::ZERO)
        .unwrap();
    assert!(matches!(
        service.authenticate(
            challenge.id,
            proof(&runtime_binding(8, 3), [1; 32], [2; 32]),
            [3; 32],
            Duration::ZERO
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    assert!(matches!(
        service.authenticate(
            challenge.id,
            proof(&binding, [1; 32], [2; 32]),
            [3; 32],
            Duration::ZERO
        ),
        Err(LocalSessionError::Unauthorized)
    ));
    let expired = service
        .issue_challenge([5; 32], [4; 32], Duration::ZERO)
        .unwrap();
    assert!(matches!(
        service.authenticate(
            expired.id,
            proof(&binding, [4; 32], [5; 32]),
            [6; 32],
            Duration::from_secs(31)
        ),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn challenge_and_session_limits_are_bounded_and_expire_absolutely() {
    let binding = runtime_binding(7, 3);
    let mut service = LocalSessionService::new(binding.clone(), SECRET);
    for value in 0u8..32 {
        service
            .issue_challenge([value; 32], [value.wrapping_add(1); 32], Duration::ZERO)
            .unwrap();
    }
    assert!(matches!(
        service.issue_challenge([99; 32], [98; 32], Duration::ZERO),
        Err(LocalSessionError::Unavailable)
    ));
    let mut rate = LocalSessionService::new(binding.clone(), SECRET);
    for value in 0u8..60 {
        let challenge = rate
            .issue_challenge(
                [value; 32],
                [value.wrapping_add(1); 32],
                Duration::from_secs(40),
            )
            .unwrap();
        assert!(matches!(
            rate.authenticate(
                challenge.id,
                BootstrapProof::new([0; 32]),
                [0; 32],
                Duration::from_secs(40)
            ),
            Err(LocalSessionError::Unauthorized)
        ));
    }
    assert!(matches!(
        rate.issue_challenge([99; 32], [98; 32], Duration::from_secs(40)),
        Err(LocalSessionError::Unavailable)
    ));
    let mut sessions = LocalSessionService::new(binding.clone(), SECRET);
    let first_authority = [2; 32];
    for value in 0u8..8 {
        let c = sessions
            .issue_challenge([value; 32], [value + 1; 32], Duration::ZERO)
            .unwrap();
        let issued = sessions
            .authenticate(
                c.id,
                proof(&binding, [value + 1; 32], [value; 32]),
                [value + 2; 32],
                Duration::ZERO,
            )
            .unwrap();
        assert_eq!(issued.binding, binding);
    }
    let c = sessions
        .issue_challenge([9; 32], [10; 32], Duration::ZERO)
        .unwrap();
    assert!(matches!(
        sessions.authenticate(
            c.id,
            proof(&binding, [10; 32], [9; 32]),
            [11; 32],
            Duration::ZERO
        ),
        Err(LocalSessionError::Unavailable)
    ));
    assert!(matches!(
        sessions.authorize_wire(&first_authority, Duration::from_secs(601)),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn epoch_revocation_and_restart_generation_mismatch_revoke_sessions() {
    let binding = runtime_binding(7, 3);
    let mut service = LocalSessionService::new(binding.clone(), SECRET);
    let c = service
        .issue_challenge([2; 32], [1; 32], Duration::ZERO)
        .unwrap();
    let _issued = service
        .authenticate(
            c.id,
            proof(&binding, [1; 32], [2; 32]),
            [3; 32],
            Duration::ZERO,
        )
        .unwrap();
    service.set_authorization_epoch(4);
    assert!(matches!(
        service.authorize_wire(&[3; 32], Duration::ZERO),
        Err(LocalSessionError::Unauthorized)
    ));
    assert!(matches!(
        service.authorize_wire_for_binding(&[3; 32], &runtime_binding(8, 4), Duration::ZERO),
        Err(LocalSessionError::Unauthorized)
    ));
}

#[test]
fn replay_authorization_reads_current_epoch_and_sensitivity_ceiling() {
    let binding = runtime_binding(7, 3);
    let mut service = LocalSessionService::new(binding, SECRET);

    let initial = service
        .current_replay_authorization("local-owner", 7)
        .unwrap();
    assert_eq!(initial.authorization_epoch(), 3);
    assert_eq!(initial.sensitivity_ceiling(), Sensitivity::Internal);

    service.set_sensitivity_ceiling(Sensitivity::Public);
    let downgraded = service
        .current_replay_authorization("local-owner", 7)
        .unwrap();
    assert_eq!(downgraded.authorization_epoch(), 3);
    assert_eq!(downgraded.sensitivity_ceiling(), Sensitivity::Public);

    service.set_authorization_epoch(4);
    let revoked = service
        .current_replay_authorization("local-owner", 7)
        .unwrap();
    assert_eq!(revoked.authorization_epoch(), 4);
    assert_eq!(revoked.sensitivity_ceiling(), Sensitivity::Public);
    assert!(matches!(
        service.current_replay_authorization("other", 7),
        Err(LocalSessionError::Unauthorized)
    ));
}
