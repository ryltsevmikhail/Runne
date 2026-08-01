#[tokio::test]
async fn race_dual_dispatch_same_permit_idempotent() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let transaction = valid_tx("intent-a", "permit-a");

    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        transaction.clone(),
        second_store,
        transaction,
    )
    .await;

    assert_eq!(first_result, second_result);
    assert!(matches!(
        first_result,
        Ok(PreEffectTransactionOutcome::Committed { ref intent_id }) if intent_id == "intent-a"
    ));
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

#[tokio::test]
async fn race_same_permit_with_different_intents_rejects_one_without_mutation() {
    let (_directory, first_store, second_store) = shared_sqlite_stores();
    let (first_result, second_result) = concurrent_commits(
        first_store.clone(),
        valid_tx("intent-a", "permit-shared"),
        second_store,
        valid_tx("intent-b", "permit-shared"),
    )
    .await;
    let outcomes = [first_result, second_result];

    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| {
                matches!(result, Err(AtomicTransactionError::PermitIntentConflict))
            })
            .count(),
        1
    );
    assert_eq!(first_store.committed_count().unwrap(), 1);
}

fn valid_tx(intent: &str, permit_id: &str) -> AtomicPreEffectTransaction {
    AtomicPreEffectTransaction {
        authorization_decision: AuthorizationDecision {
            grant_id: "grant-1".into(),
            allowed: true,
            reason: "authorized".into(),
        },
        budget_reservation_id: format!("reservation-{intent}"),
        budget_amount: 1,
        side_effect_started: true,
        dispatch_intent: intent.into(),
        permit_id: permit_id.into(),
    }
}

#[tokio::test]
#[cfg(not(target_os = "windows"))]
async fn race_toc_tou_replacement_is_rejected_by_production_broker() {
    let test_root =
        std::env::temp_dir().join(format!("gocode-security-race-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&test_root).unwrap();
    let broker = Arc::new(FilesystemBroker::new(vec![WorkspaceRoot {
        root_id: "race-root".into(),
        canonical_path: std::fs::canonicalize(&test_root).unwrap(),
        policy: WorkspacePolicy {
            read_allowed: true,
            write_allowed: true,
            create_allowed: true,
            delete_allowed: true,
            symlink_policy: SymlinkPolicy::NoFollow,
        },
    }]));
    let root = broker.open_root("race-root").unwrap();
    let path = CanonicalPath::new("target.txt").unwrap();
    std::fs::write(test_root.join("target.txt"), b"original").unwrap();
    let (_, identity_before) = broker.resolve_and_identity(&root, &path).unwrap();
    let writer_done = Arc::new(Barrier::new(2));
    let writer_barrier = writer_done.clone();
    let writer_root = test_root.clone();
    let writer = async move {
        let replacement = writer_root.join("replacement.tmp");
        std::fs::write(&replacement, b"replacement").unwrap();
        std::fs::rename(replacement, writer_root.join("target.txt")).unwrap();
        writer_barrier.wait().await;
    };
    let checker_barrier = writer_done.clone();
    let checker_broker = broker.clone();
    let checker = async move {
        checker_barrier.wait().await;
        checker_broker.write_with_revalidation(&root, &path, b"mutated", &identity_before)
    };

    let (_, result) = tokio::join!(writer, checker);

    assert!(matches!(result, Err(FsBrokerError::MutationUnavailable)));
    assert_eq!(
        std::fs::read(test_root.join("target.txt")).unwrap(),
        b"replacement"
    );
    std::fs::remove_dir_all(test_root).unwrap();
}

#[tokio::test]
#[cfg(target_os = "windows")]
async fn race_toc_tou_production_broker_fails_closed_before_setup() {
    let test_root =
        std::env::temp_dir().join(format!("gocode-security-race-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&test_root).unwrap();
    let target = test_root.join("target.txt");
    std::fs::write(&target, b"original").unwrap();
    let broker = FilesystemBroker::new(vec![WorkspaceRoot {
        root_id: "race-root".into(),
        canonical_path: std::fs::canonicalize(&test_root).unwrap(),
        policy: WorkspacePolicy {
            read_allowed: true,
            write_allowed: true,
            create_allowed: true,
            delete_allowed: true,
            symlink_policy: SymlinkPolicy::NoFollow,
        },
    }]);

    assert!(matches!(
        broker.open_root("race-root"),
        Err(FsBrokerError::BackendUnavailable)
    ));
    assert_eq!(std::fs::read(&target).unwrap(), b"original");

    std::fs::remove_dir_all(test_root).unwrap();
}

#[tokio::test]
async fn race_dns_redirect_to_private_address_is_rejected() {
    use std::net::{IpAddr, Ipv4Addr};

    let broker = NetworkBroker::new(EgressPolicy {
        allowed_hosts: vec!["example.com".into(), "redirect.example.com".into()],
        deny_private: true,
        deny_loopback: true,
        deny_metadata: true,
        max_redirects: 3,
    });
    let initial = broker
        .resolve_destination(
            NetworkDestination {
                scheme: "https".into(),
                host: "example.com".into(),
                port: 443,
            },
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .unwrap();
    let connection = broker.connect(initial).unwrap();
    let redirect_ready = Arc::new(Barrier::new(2));
    let resolved_addresses = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let dns_barrier = redirect_ready.clone();
    let dns_addresses = resolved_addresses.clone();
    let dns_update = async move {
        *dns_addresses.lock().await = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        dns_barrier.wait().await;
    };
    let redirect_barrier = redirect_ready.clone();
    let redirect_addresses = resolved_addresses.clone();
    let redirect = async move {
        redirect_barrier.wait().await;
        let addresses = redirect_addresses.lock().await.clone();
        broker.follow_redirect(
            &connection,
            NetworkDestination {
                scheme: "https".into(),
                host: "redirect.example.com".into(),
                port: 443,
            },
            addresses,
        )
    };

    let (_, result) = tokio::join!(dns_update, redirect);

    assert!(matches!(
        result,
        Err(NetworkError::RedirectedToPrivateAddress)
    ));
}
