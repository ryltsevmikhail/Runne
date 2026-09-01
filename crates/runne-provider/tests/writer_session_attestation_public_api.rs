use std::io::Cursor;

use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget, CredentialFence,
    CredentialInstallationOwnerId, CredentialIssueTicketBindingV1, CredentialLifecycleRevision,
    CredentialOperationAction, CredentialOperationId, CredentialTicketAttempt,
    CredentialVersionRef, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionAttestationCodec, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1,
    PendingCredentialIssueTicketV1, ProviderId, RawCredentialTicket, daemon_credential_publication,
};

#[derive(Clone, Copy)]
struct TicketFacts {
    operation: u8,
    attempt: u64,
    claim: u8,
    channel: u8,
}

#[derive(Clone, Copy)]
struct RuntimeFacts {
    protected_session: u8,
    tauri_peer: u8,
    daemon_authority: u8,
    database_generation: u64,
    supervisor_generation: u64,
    release_tuple: u8,
}

#[test]
fn decoded_attestation_matches_only_exact_observable_facts() {
    let ticket_facts = TicketFacts {
        operation: 1,
        attempt: 2,
        claim: 3,
        channel: 4,
    };
    let runtime_facts = RuntimeFacts {
        protected_session: 7,
        tauri_peer: 8,
        daemon_authority: 9,
        database_generation: 10,
        supervisor_generation: 11,
        release_tuple: 12,
    };
    let process_facts = [16, 17, 18, 19, 20, 21];
    let frame_bytes = CredentialBrokerFrameCodec::encode(issue_frame(ticket_facts, 1)).unwrap();
    let issue = CredentialIssueTicketBindingV1::from_issue_ticket(
        &CredentialBrokerFrameCodec::decode(&frame_bytes).unwrap(),
    )
    .unwrap();
    let signer = daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate(
        [ticket_facts.channel; 32],
    )
    .unwrap();
    let expected_public_key = signer.public_key();
    let (signed, _) = signer
        .sign(CredentialWriterSessionAttestationClaimsV1::new(
            ticket_claims(issue, ticket_facts),
            runtime_claims(runtime_facts),
            process_claims(process_facts),
        ))
        .unwrap();
    let decoded = CredentialWriterSessionAttestationCodec::decode_and_verify(
        &CredentialWriterSessionAttestationCodec::encode(&signed),
        expected_public_key,
    )
    .unwrap();

    assert!(decoded.matches_pending_issue_ticket(&pending_ticket(&frame_bytes)));
    assert!(decoded.matches_handoff(
        &[ticket_facts.channel; 32],
        &expected_public_key,
        &[process_facts[0]; 32],
    ));
    assert!(decoded.matches_live_processes(
        &[process_facts[1]; 32],
        &[process_facts[2]; 32],
        &[process_facts[4]; 32],
        &[process_facts[5]; 32],
    ));
    assert!(decoded.matches_provisional_release_binding(&[runtime_facts.release_tuple; 32]));

    assert!(!decoded.matches_pending_issue_ticket(&pending_ticket(
        &CredentialBrokerFrameCodec::encode(issue_frame(ticket_facts, 1)).unwrap()
    )));
    assert!(
        !decoded.matches_pending_issue_ticket(&pending_ticket(&mutated_issue_bytes(
            &frame_bytes,
            ticket_facts,
            2
        )))
    );
    for mutation in [
        TicketFacts {
            operation: 22,
            ..ticket_facts
        },
        TicketFacts {
            attempt: 23,
            ..ticket_facts
        },
        TicketFacts {
            claim: 24,
            ..ticket_facts
        },
        TicketFacts {
            channel: 25,
            ..ticket_facts
        },
    ] {
        assert!(
            !decoded.matches_pending_issue_ticket(&pending_ticket(&mutated_issue_bytes(
                &frame_bytes,
                mutation,
                1
            )))
        );
    }

    for (channel, public_key, handoff) in [
        ([25; 32], expected_public_key, [process_facts[0]; 32]),
        ([ticket_facts.channel; 32], [26; 32], [process_facts[0]; 32]),
        ([ticket_facts.channel; 32], expected_public_key, [27; 32]),
    ] {
        assert!(!decoded.matches_handoff(&channel, &public_key, &handoff));
    }

    for index in [1, 2, 4, 5] {
        let mut mutation = process_facts;
        mutation[index] = 32 + u8::try_from(index).unwrap();
        assert!(!decoded.matches_live_processes(
            &[mutation[1]; 32],
            &[mutation[2]; 32],
            &[mutation[4]; 32],
            &[mutation[5]; 32],
        ));
    }
    assert!(!decoded.matches_provisional_release_binding(&[31; 32]));
}

fn mutated_issue_bytes(frame_bytes: &[u8], facts: TicketFacts, version: u64) -> Vec<u8> {
    let CredentialBrokerFrame::IssueTicket { ticket, .. } =
        CredentialBrokerFrameCodec::decode(frame_bytes).unwrap()
    else {
        unreachable!()
    };
    CredentialBrokerFrameCodec::encode(issue_frame_with_ticket(facts, version, ticket)).unwrap()
}

fn pending_ticket(frame_bytes: &[u8]) -> PendingCredentialIssueTicketV1 {
    PendingCredentialIssueTicketV1::read_from(&mut Cursor::new(frame_bytes)).unwrap()
}

fn issue_frame(facts: TicketFacts, version: u64) -> CredentialBrokerFrame {
    issue_frame_with_ticket(facts, version, RawCredentialTicket::generate().unwrap())
}

fn issue_frame_with_ticket(
    facts: TicketFacts,
    version: u64,
    ticket: RawCredentialTicket,
) -> CredentialBrokerFrame {
    let operation_id = CredentialOperationId::from_bytes([facts.operation; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(facts.attempt).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket,
        channel_binding: [facts.channel; 32],
        binding: digest(facts.claim),
        command: CredentialBrokerCommand::new(
            operation_id,
            attempt,
            provider.clone(),
            CredentialOperationAction::Pair,
            CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, version).unwrap()),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            None,
        )
        .unwrap(),
    }
}

fn ticket_claims(
    issue: CredentialIssueTicketBindingV1,
    facts: TicketFacts,
) -> CredentialWriterSessionTicketClaimsV1 {
    CredentialWriterSessionTicketClaimsV1::new(
        CredentialOperationId::from_bytes([facts.operation; 16]).unwrap(),
        CredentialTicketAttempt::new(facts.attempt).unwrap(),
        issue,
        digest(facts.claim),
        CredentialInstallationOwnerId::from_bytes([5; 32]).unwrap(),
        digest(6),
        13,
        14,
    )
    .unwrap()
}

fn runtime_claims(facts: RuntimeFacts) -> CredentialWriterSessionRuntimeClaimsV1 {
    CredentialWriterSessionRuntimeClaimsV1::new(
        digest(facts.protected_session),
        digest(facts.tauri_peer),
        digest(facts.daemon_authority),
        facts.database_generation,
        facts.supervisor_generation,
        digest(facts.release_tuple),
    )
    .unwrap()
}

fn process_claims(facts: [u8; 6]) -> CredentialWriterSessionProcessClaimsV1 {
    CredentialWriterSessionProcessClaimsV1::new(
        digest(facts[0]),
        digest(facts[1]),
        digest(facts[2]),
        digest(facts[3]),
        digest(facts[4]),
        digest(facts[5]),
    )
    .unwrap()
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
