    use super::*;

    #[test]
    fn test_operation_tag_discriminants() {
        assert_eq!(OperationTag::CreateTaskRun as u8, 1);
        assert_eq!(OperationTag::Queue as u8, 2);
        assert_eq!(OperationTag::Admit as u8, 3);
        assert_eq!(OperationTag::StartAttempt as u8, 4);
        assert_eq!(OperationTag::Complete as u8, 5);
        assert_eq!(OperationTag::CreateConversation as u8, 6);
        assert_eq!(OperationTag::StartLoopCycle as u8, 7);
        assert_eq!(OperationTag::CommitContext as u8, 8);
        assert_eq!(OperationTag::CommitPlan as u8, 9);
        assert_eq!(OperationTag::RecordStepOutcome as u8, 10);
        assert_eq!(OperationTag::CompleteLoopCycle as u8, 11);
        assert_eq!(OperationTag::CreateNextCycle as u8, 12);
        assert_eq!(OperationTag::ScheduleRetry as u8, 13);
        assert_eq!(OperationTag::ActivateScheduledRetryAttempt as u8, 14);
        assert_eq!(OperationTag::CommitRecoveryResume as u8, 15);
        assert_eq!(OperationTag::CommitLoopCheckpoint as u8, 16);
        assert_eq!(OperationTag::ResumeLoopWait as u8, 17);
        assert_eq!(OperationTag::GenerateConversationText as u8, 18);
    }

    #[test]
    fn test_receipt_lookup_clone_eq() {
        let miss1 = ReceiptLookup::Miss;
        let miss2 = ReceiptLookup::Miss;
        assert_eq!(miss1, miss2);
    }

    #[test]
    fn test_commit_error_clone_eq() {
        let err1 = CommitError::VersionConflict {
            expected: 1,
            actual: 2,
        };
        let err2 = CommitError::VersionConflict {
            expected: 1,
            actual: 2,
        };
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_storage_failure_kind_values() {
        // Ensure all variants are distinguishable
        assert_ne!(
            StorageFailureKind::CorruptData,
            StorageFailureKind::UnsupportedSchema
        );
        assert_ne!(
            StorageFailureKind::IntegrityViolation,
            StorageFailureKind::Unavailable
        );
    }

    #[test]
    fn test_idempotency_scope_clone_eq() {
        let scope1 = IdempotencyScope {
            runtime_authority_id: RuntimeAuthorityId("host-1".into()),
            principal_id: PrincipalId("user-1".into()),
            operation: OperationTag::CreateTaskRun,
            aggregate_scope: AggregateScope::NewTaskRun {
                conversation_id: "018f2e3a-7000-7000-8000-000000000001".parse().unwrap(),
                workspace_id: "018f2e3a-7000-7000-8000-000000000002".parse().unwrap(),
            },
        };
        let scope2 = scope1.clone();
        assert_eq!(scope1, scope2);
    }
