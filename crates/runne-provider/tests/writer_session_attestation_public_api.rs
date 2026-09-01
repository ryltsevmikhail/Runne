use runne_provider::{
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget, CredentialFence,
    CredentialInstallationOwnerId, CredentialIssueTicketBindingV1, CredentialLifecycleRevision,
    CredentialOperationAction, CredentialOperationId, CredentialTicketAttempt,
    CredentialVersionRef, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionAttestationCodec, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1, ProviderId,
    RawCredentialTicket, daemon_credential_publication,
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
fn decoded_claims_compare_to_independently_constructed_exact_expectations() {
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

    let expected_ticket = ticket_claims(issue, ticket_facts);
    let expected_runtime = runtime_claims(runtime_facts);
    let expected_process = process_claims(process_facts);
    assert!(decoded.ticket_claims() == &expected_ticket);
    assert!(decoded.runtime_claims() == &expected_runtime);
    assert!(decoded.process_claims() == &expected_process);

    let digest_mutation = issue_binding(&frame_bytes, ticket_facts, 2);
    assert!(decoded.ticket_claims() != &ticket_claims(digest_mutation, ticket_facts));
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
        let mutated_issue = issue_binding(&frame_bytes, mutation, 1);
        assert!(decoded.ticket_claims() != &ticket_claims(mutated_issue, mutation));
    }

    for mutation in [
        RuntimeFacts {
            protected_session: 26,
            ..runtime_facts
        },
        RuntimeFacts {
            tauri_peer: 27,
            ..runtime_facts
        },
        RuntimeFacts {
            daemon_authority: 28,
            ..runtime_facts
        },
        RuntimeFacts {
            database_generation: 29,
            ..runtime_facts
        },
        RuntimeFacts {
            supervisor_generation: 30,
            ..runtime_facts
        },
        RuntimeFacts {
            release_tuple: 31,
            ..runtime_facts
        },
    ] {
        assert!(decoded.runtime_claims() != &runtime_claims(mutation));
    }

    for index in 0..process_facts.len() {
        let mut mutation = process_facts;
        mutation[index] = 32 + u8::try_from(index).unwrap();
        assert!(decoded.process_claims() != &process_claims(mutation));
    }
}

fn issue_binding(
    frame_bytes: &[u8],
    facts: TicketFacts,
    version: u64,
) -> CredentialIssueTicketBindingV1 {
    let CredentialBrokerFrame::IssueTicket { ticket, .. } =
        CredentialBrokerFrameCodec::decode(frame_bytes).unwrap()
    else {
        unreachable!()
    };
    CredentialIssueTicketBindingV1::from_issue_ticket(&issue_frame_with_ticket(
        facts, version, ticket,
    ))
    .unwrap()
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
