use super::*;

#[test]
fn errors_and_unwinds_at_capture_emission_or_revalidation_never_dispatch_remove() {
    for phase in 1..=5 {
        for panic in [false, true] {
            let mut b = backend(fixture().1);
            b.fault = phase;
            b.panic = panic;
            let removed = b.removed.clone();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(b)));
            if panic {
                assert!(outcome.is_err());
            } else {
                assert!(outcome.unwrap().is_err());
            }
            assert!(!removed.get());
        }
    }
}
#[test]
fn bounded_record_preserves_raw_data_and_rejects_overflow() {
    let (e, o) = fixture();
    let bytes = record(&e, &o).unwrap();
    assert!(bytes.len() <= RECORD_MAX);
    let json: serde_json::Value =
        serde_json::from_slice(&bytes[b"F1_CLEANUP_V1 ".len()..]).unwrap();
    assert_eq!(json["phase"], "PRE_REMOVE");
    assert_eq!(json["identity_hex"], hex(&e.identity));
    assert_eq!(json["events_hex"], hex(&o.events));
    assert_eq!(json["procs_hex"], "");
    let mut writer = BoundedRecord(Vec::new());
    writer.write_all(&vec![0; RECORD_MAX]).unwrap();
    assert!(writer.write_all(b"x").is_err());
}
#[test]
fn actual_inventory_decoder_rejects_truncation_errors_and_caps() {
    fn row(name: &[u8], kind: u8, ino: u64) -> Vec<u8> {
        let len = (20 + name.len() + 7) & !7;
        let mut row = vec![0; len];
        row[..8].copy_from_slice(&ino.to_ne_bytes());
        row[16..18].copy_from_slice(&(len as u16).to_ne_bytes());
        row[18] = kind;
        row[19..19 + name.len()].copy_from_slice(name);
        row
    }
    let good = row(b"cgroup.procs", libc::DT_REG, 8);
    let mut entries = Vec::new();
    let mut bytes = 0;
    inventory::append(&good, &mut entries, &mut bytes).unwrap();
    assert_eq!(entries[0].name, "cgroup.procs");
    assert_eq!(bytes, good.len());
    for bad in [
        good[..19].to_vec(),
        good[..good.len() - 1].to_vec(),
        row(b"../x", libc::DT_REG, 8),
        row(b"", libc::DT_REG, 8),
        row(b"x", libc::DT_REG, 0),
        vec![255; 24],
    ] {
        assert!(inventory::append(&bad, &mut Vec::new(), &mut 0).is_err());
    }
    let mut total = INVENTORY_MAX;
    assert!(inventory::append(&good, &mut Vec::new(), &mut total).is_err());
    let mut entries = vec![fixture().1.entries[0].clone(); ENTRY_MAX];
    assert!(inventory::append(&good, &mut entries, &mut 0).is_err());
}

#[test]
fn actual_bounded_reader_requires_eof_and_propagates_read_failure() {
    struct Broken;
    impl std::io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> Result<usize> {
            Err(refuse())
        }
    }
    assert_eq!(capture::bounded(&b""[..], 0).unwrap(), b"");
    assert!(capture::bounded(&b"x"[..], 0).is_err());
    assert!(capture::bounded(Broken, CONTROL_MAX).is_err());
    assert!(capture::bounded(&vec![0; CONTROL_MAX + 1][..], CONTROL_MAX).is_err());
}
#[test]
fn checked_emission_propagates_partial_write_zero_flush_error_and_panic() {
    struct Broken {
        mode: usize,
        calls: usize,
    }
    impl Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> Result<usize> {
            self.calls += 1;
            match self.mode {
                0 if self.calls == 1 => Ok(bytes.len().min(1)),
                0 => Err(refuse()),
                1 => Ok(0),
                2 => Ok(bytes.len()),
                _ => panic!("injected output panic"),
            }
        }
        fn flush(&mut self) -> Result<()> {
            Err(refuse())
        }
    }
    let (e, o) = fixture();
    for mode in 0..=3 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            emit_to(&mut Broken { mode, calls: 0 }, &e, &o)
        }));
        if mode == 3 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
    }
}

#[test]
fn core_and_cpu_accounting_pseudofiles_are_accepted_as_regular_metadata_entries() {
    let (e, mut o) = fixture();
    for (index, name) in [
        "cgroup.stat.local",
        "cpu.stat",
        "cpu.stat.local",
        "irq.pressure",
    ]
    .into_iter()
    .enumerate()
    {
        o.entries.push(Entry {
            name: name.into(),
            kind: libc::DT_REG,
            ino: 20 + index as u64,
        });
        o.inventory_bytes += 64;
    }
    validate(&e, &o).unwrap();
    let b = backend(o);
    let removed = b.removed.clone();
    dispatch(b).unwrap();
    assert!(
        removed.get(),
        "complete metadata observation reaches the shared dispatch"
    );
}
#[test]
fn cpu_controls_unknown_names_and_nonregular_compatibility_entries_still_refuse() {
    for name in [
        "cpu.max",
        "cpu.max.burst",
        "cpu.weight",
        "cpu.stat.unknown",
        "unknown",
    ] {
        let mut o = fixture().1;
        o.entries.push(Entry {
            name: name.into(),
            kind: libc::DT_REG,
            ino: 20,
        });
        o.inventory_bytes += 64;
        rejected(o);
    }
    for name in [
        "cgroup.stat.local",
        "cpu.stat",
        "cpu.stat.local",
        "irq.pressure",
    ] {
        for kind in [libc::DT_DIR, libc::DT_LNK, libc::DT_UNKNOWN] {
            let mut o = fixture().1;
            o.entries.push(Entry {
                name: name.into(),
                kind,
                ino: 20,
            });
            o.inventory_bytes += 64;
            rejected(o);
        }
    }
}
