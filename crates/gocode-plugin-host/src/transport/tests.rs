    use std::{
        collections::HashMap,
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;

    #[derive(Clone, Default)]
    struct MemoryJournal(Arc<Mutex<MemoryJournalState>>);

    #[derive(Default)]
    struct MemoryJournalState {
        entries: HashMap<PluginActivationId, (PluginStartIntentBinding, [u8; 32])>,
        next: u64,
    }

    impl MemoryJournal {
        fn row_count(&self) -> usize {
            self.0.lock().unwrap().entries.len()
        }

        fn allocation_count(&self) -> u64 {
            self.0.lock().unwrap().next
        }
    }

    impl PluginStartIntentJournal for MemoryJournal {
        fn reserve_or_lookup(
            &self,
            binding: &PluginStartIntentBinding,
        ) -> Result<PluginStartIntentJournalResult, PluginStartIntentJournalError> {
            let mut state = self.0.lock().unwrap();
            if let Some((stored, reservation)) = state.entries.get(binding.activation_id()) {
                return if stored == binding {
                    Ok(PluginStartIntentJournalResult::Existing(*reservation))
                } else {
                    Err(PluginStartIntentJournalError::Conflict)
                };
            }
            state.next += 1;
            let mut reservation = [0; 32];
            reservation[..8].copy_from_slice(&state.next.to_be_bytes());
            state.entries.insert(
                binding.activation_id().clone(),
                (binding.clone(), reservation),
            );
            Ok(PluginStartIntentJournalResult::Fresh(reservation))
        }
    }

    #[derive(Clone)]
    struct RaceJournal {
        journal: MemoryJournal,
        entered: Arc<AtomicUsize>,
        entrants_before_first_mutation: Arc<AtomicUsize>,
        barrier: Arc<Barrier>,
    }

    impl RaceJournal {
        fn new() -> Self {
            Self {
                journal: MemoryJournal::default(),
                entered: Arc::new(AtomicUsize::new(0)),
                entrants_before_first_mutation: Arc::new(AtomicUsize::new(0)),
                barrier: Arc::new(Barrier::new(2)),
            }
        }

        fn entered_calls(&self) -> usize {
            self.entered.load(Ordering::SeqCst)
        }

        fn row_count(&self) -> usize {
            self.journal.row_count()
        }

        fn allocation_count(&self) -> u64 {
            self.journal.allocation_count()
        }

        fn entrants_before_first_mutation(&self) -> usize {
            self.entrants_before_first_mutation.load(Ordering::SeqCst)
        }
    }

    impl PluginStartIntentJournal for RaceJournal {
        fn reserve_or_lookup(
            &self,
            binding: &PluginStartIntentBinding,
        ) -> Result<PluginStartIntentJournalResult, PluginStartIntentJournalError> {
            let entrant = self.entered.fetch_add(1, Ordering::SeqCst);
            if entrant < 2 {
                self.barrier.wait();
            }
            let entrants = self.entered.load(Ordering::SeqCst);
            let _ = self.entrants_before_first_mutation.compare_exchange(
                0,
                entrants,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            self.journal.reserve_or_lookup(binding)
        }
    }

    #[test]
    fn durable_authority_replays_exact_binding_across_restart_but_rejects_stale_binding() {
        let journal = MemoryJournal::default();
        let activation = PluginActivationId::new("durable-activation").unwrap();
        let digest = PluginDigest::from_bytes([1; 32]);
        let first = DurablePluginStartIntentAuthority::new(journal.clone())
            .reserve(&activation, digest, PluginGeneration::INITIAL)
            .unwrap();
        let replay = DurablePluginStartIntentAuthority::new(journal.clone())
            .reserve(&activation, digest, PluginGeneration::INITIAL)
            .unwrap();
        assert_eq!(first.reservation(), replay.reservation());
        assert_eq!(first.origin(), PluginStartIntentOrigin::Fresh);
        assert_eq!(replay.origin(), PluginStartIntentOrigin::Existing);

        let different = DurablePluginStartIntentAuthority::new(journal).reserve(
            &activation,
            digest,
            PluginGeneration::new(2).unwrap(),
        );
        assert_eq!(different, Err(PluginStartIntentPortError::Conflict));
    }

    #[test]
    fn durable_authority_never_reuses_a_reservation_for_distinct_activation() {
        let journal = MemoryJournal::default();
        let authority = DurablePluginStartIntentAuthority::new(journal);
        let digest = PluginDigest::from_bytes([1; 32]);
        let first = authority
            .reserve(
                &PluginActivationId::new("first").unwrap(),
                digest,
                PluginGeneration::INITIAL,
            )
            .unwrap();
        let second = authority
            .reserve(
                &PluginActivationId::new("second").unwrap(),
                digest,
                PluginGeneration::INITIAL,
            )
            .unwrap();
        assert_ne!(first.reservation(), second.reservation());
    }

    #[test]
    fn durable_authority_restart_replays_and_distinct_activation_gets_a_new_journal_row() {
        let journal = MemoryJournal::default();
        let digest = PluginDigest::from_bytes([3; 32]);
        let first_id = PluginActivationId::new("restart-first").unwrap();
        let first = DurablePluginStartIntentAuthority::new(journal.clone())
            .reserve(&first_id, digest, PluginGeneration::INITIAL)
            .unwrap();
        let reconstructed = DurablePluginStartIntentAuthority::new(journal.clone());
        let replay = reconstructed
            .reserve(&first_id, digest, PluginGeneration::INITIAL)
            .unwrap();
        let distinct = reconstructed
            .reserve(
                &PluginActivationId::new("restart-distinct").unwrap(),
                digest,
                PluginGeneration::INITIAL,
            )
            .unwrap();

        assert_eq!(first.reservation(), replay.reservation());
        assert_eq!(first.origin(), PluginStartIntentOrigin::Fresh);
        assert_eq!(replay.origin(), PluginStartIntentOrigin::Existing);
        assert_ne!(first.reservation(), distinct.reservation());
        assert_eq!(journal.row_count(), 2);
    }

    #[test]
    fn durable_authority_two_thread_reserve_race_creates_one_row_and_stable_token() {
        let journal = RaceJournal::new();
        let left_authority =
            std::sync::Arc::new(DurablePluginStartIntentAuthority::new(journal.clone()));
        let right_authority =
            std::sync::Arc::new(DurablePluginStartIntentAuthority::new(journal.clone()));
        let activation = PluginActivationId::new("reserve-race").unwrap();
        let digest = PluginDigest::from_bytes([4; 32]);
        let left = {
            let authority = left_authority.clone();
            let activation = activation.clone();
            std::thread::spawn(move || {
                authority
                    .reserve(&activation, digest, PluginGeneration::INITIAL)
                    .unwrap()
            })
        };
        let right = {
            let authority = right_authority.clone();
            let activation = activation.clone();
            std::thread::spawn(move || {
                authority
                    .reserve(&activation, digest, PluginGeneration::INITIAL)
                    .unwrap()
            })
        };
        let left = left.join().unwrap();
        let right = right.join().unwrap();

        assert_eq!(left.reservation(), right.reservation());
        assert_eq!(journal.entered_calls(), 2);
        assert_eq!(journal.entrants_before_first_mutation(), 2);
        let replay = DurablePluginStartIntentAuthority::new(journal.clone())
            .reserve(&activation, digest, PluginGeneration::INITIAL)
            .unwrap();
        assert_eq!(left.reservation(), replay.reservation());
        assert_eq!(journal.entered_calls(), 3);
        assert_eq!(journal.row_count(), 1);
        assert_eq!(journal.allocation_count(), 1);
    }
