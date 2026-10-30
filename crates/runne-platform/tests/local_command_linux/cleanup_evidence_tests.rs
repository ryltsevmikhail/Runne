#![cfg(test)]
#[path = "cleanup_evidence_test_boundaries.rs"]
mod boundaries;
use super::validation::{CONTROL_MAX, ENTRY_MAX, Entry, INVENTORY_MAX, Stat};
use super::*;
use std::cell::Cell;
use std::rc::Rc;

fn fixture() -> (Expected, Observation) {
    let mut identity = [0u8; 100];
    identity[..4].copy_from_slice(b"RMA1");
    identity[4..20].fill(1);
    for (start, number) in [(20, 2u64), (28, 3), (36, 2), (44, 4)] {
        identity[start..start + 8].copy_from_slice(&number.to_be_bytes());
    }
    identity[52..].fill(5);
    let expected = Expected {
        identity,
        binding: [5; 48],
        uid: 6,
        gid: 7,
    };
    let entries = [
        (".", libc::DT_DIR, 4),
        ("..", libc::DT_DIR, 3),
        ("cgroup.procs", libc::DT_REG, 8),
        ("cgroup.events", libc::DT_REG, 9),
    ]
    .into_iter()
    .map(|(name, kind, ino)| Entry {
        name: name.into(),
        kind,
        ino,
    })
    .collect();
    let observation = Observation {
        boot: [1; 16],
        h: Stat {
            dev: 2,
            ino: 3,
            uid: 6,
            gid: 7,
        },
        a: Stat {
            dev: 2,
            ino: 4,
            uid: 6,
            gid: 7,
        },
        name: format!("runne-{}", hex(&expected.binding)),
        procs: Some(Vec::new()),
        procs_eof: true,
        events_eof: true,
        events: b"populated 0\nfrozen 0\n".to_vec(),
        entries,
        inventory_eof: true,
        inventory_bytes: 128,
    };
    (expected, observation)
}
impl Observed for Observation {
    fn observation(&self) -> &Observation {
        self
    }
}
struct Injected {
    expected: Expected,
    observation: Observation,
    fault: usize,
    panic: bool,
    calls: Rc<Cell<usize>>,
    removed: Rc<Cell<bool>>,
}
impl Injected {
    fn step(&self, n: usize) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        if self.fault == n {
            assert!(!self.panic, "injected phase panic");
            return Err(refuse());
        }
        Ok(())
    }
}
impl Backend for Injected {
    type Held = Observation;
    fn expected(&self) -> &Expected {
        &self.expected
    }
    fn capture(&mut self) -> Result<Observation> {
        self.step(1)?;
        Ok(self.observation.clone())
    }
    fn emit(&mut self, held: &Observation) -> Result<()> {
        self.step(2)?;
        if self.fault == 4 {
            struct FailingWriter(bool);
            impl Write for FailingWriter {
                fn write(&mut self, _: &[u8]) -> Result<usize> {
                    assert!(!self.0, "injected write panic");
                    Err(refuse())
                }
                fn flush(&mut self) -> Result<()> {
                    Ok(())
                }
            }
            return emit_to(&mut FailingWriter(self.panic), &self.expected, held);
        }
        emit_to(&mut Vec::new(), &self.expected, held)?;
        Ok(())
    }
    fn revalidate(&mut self, held: &Observation) -> Result<()> {
        self.step(3)?;
        let mut fresh = held.clone();
        if self.fault == 5 {
            assert!(!self.panic, "injected revalidation panic");
            fresh.a.uid += 1;
        }
        validation::identity(&self.expected, &fresh)
    }
    fn remove(self, _held: Observation) -> Result<()> {
        self.removed.set(true);
        Ok(())
    }
}
fn backend(observation: Observation) -> Injected {
    Injected {
        expected: fixture().0,
        observation,
        fault: 0,
        panic: false,
        calls: Rc::new(Cell::new(0)),
        removed: Rc::new(Cell::new(false)),
    }
}
fn rejected(o: Observation) {
    let b = backend(o);
    let removed = b.removed.clone();
    let calls = b.calls.clone();
    assert!(dispatch(b).is_err());
    assert!(!removed.get());
    assert_eq!(
        calls.get(),
        1,
        "invalid observation must stop before emission"
    );
}
#[test]
fn complete_observation_reaches_the_shared_remove_dispatch() {
    let b = backend(fixture().1);
    let removed = b.removed.clone();
    let calls = b.calls.clone();
    dispatch(b).unwrap();
    assert!(removed.get());
    assert_eq!(calls.get(), 3);
}
#[test]
fn missing_truncated_nonempty_or_malformed_procs_refuse() {
    for value in [
        None,
        Some(b"1\n".to_vec()),
        Some(b"garbage".to_vec()),
        Some(vec![0]),
    ] {
        let mut o = fixture().1;
        o.procs = value;
        rejected(o);
    }
    let mut o = fixture().1;
    o.procs_eof = false;
    rejected(o);
}
#[test]
fn strict_events_reject_missing_duplicates_population_and_malformed_fields() {
    for raw in [
        "",
        "populated 1\n",
        "populated 0",
        "frozen 0\n",
        "populated 0\npopulated 0\n",
        "populated 0\nfrozen 0\nfrozen 1\n",
        "populated 0\nunknown 0\n",
        "populated 00\n",
        "populated 0\n\n",
        "populated 0\nfrozen 2\n",
    ] {
        let mut o = fixture().1;
        o.events = raw.as_bytes().to_vec();
        rejected(o);
    }
    let mut o = fixture().1;
    o.events_eof = false;
    rejected(o);
    let mut o = fixture().1;
    o.events = vec![b'x'; CONTROL_MAX + 1];
    rejected(o);
}
#[test]
fn incomplete_or_unsafe_inventory_cannot_dispatch_removal() {
    let mut o = fixture().1;
    o.inventory_eof = false;
    rejected(o);
    let mut o = fixture().1;
    o.inventory_bytes = INVENTORY_MAX + 1;
    rejected(o);
    let mut o = fixture().1;
    o.entries = vec![o.entries[0].clone(); ENTRY_MAX + 1];
    rejected(o);
    for (name, kind) in [
        ("child", libc::DT_DIR),
        ("cgroup.procs", libc::DT_LNK),
        ("unknown", libc::DT_REG),
        ("cgroup.procs", libc::DT_UNKNOWN),
        ("cgroup.procs", libc::DT_FIFO),
        ("../cgroup.procs", libc::DT_REG),
    ] {
        let mut o = fixture().1;
        o.entries[2] = Entry {
            name: name.into(),
            kind,
            ino: 8,
        };
        rejected(o);
    }
    let mut o = fixture().1;
    o.entries.remove(2);
    rejected(o);
    let mut o = fixture().1;
    o.entries.push(o.entries[2].clone());
    rejected(o);
    let mut o = fixture().1;
    o.entries[0].ino += 1;
    rejected(o);
    let mut o = fixture().1;
    o.entries[1].ino += 1;
    rejected(o);
}
#[test]
fn boot_name_binding_devices_inodes_uid_and_gid_drift_refuse() {
    for field in 0..11 {
        let mut o = fixture().1;
        match field {
            0 => o.boot[0] ^= 1,
            1 => o.name.push('0'),
            2 => o.h.dev += 1,
            3 => o.h.ino += 1,
            4 => o.a.dev += 1,
            5 => o.a.ino += 1,
            6 => o.h.uid += 1,
            7 => o.a.uid += 1,
            8 => o.h.gid += 1,
            9 => o.a.gid += 1,
            _ => o.boot = [0; 16],
        }
        rejected(o);
    }
    for index in [0, 4, 20, 28, 36, 44, 52, 99] {
        let (mut e, o) = fixture();
        e.identity[index] ^= 1;
        assert!(validate(&e, &o).is_err());
    }
    let (mut e, o) = fixture();
    e.binding[0] ^= 1;
    assert!(validate(&e, &o).is_err());
}
