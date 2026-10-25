//! Private synchronous evidence gate; outer writer exclusivity is a separate premise.
use runne_platform::process_managed_area::LinuxManagedArea;
use std::io::{self, Write};
#[path = "cleanup_evidence_capture.rs"]
mod capture;
#[path = "cleanup_evidence_inventory.rs"]
mod inventory;
#[path = "cleanup_evidence_tests.rs"]
mod tests;
#[path = "cleanup_evidence_validation.rs"]
mod validation;
use validation::{Expected, Observation, validate};
type Result<T> = io::Result<T>;
fn refuse() -> io::Error {
    io::Error::other("F1 cleanup evidence refused")
}

trait Observed {
    fn observation(&self) -> &Observation;
}
trait Backend {
    type Held: Observed;
    fn expected(&self) -> &Expected;
    fn capture(&mut self) -> Result<Self::Held>;
    fn emit(&mut self, held: &Self::Held) -> Result<()>;
    fn revalidate(&mut self, held: &Self::Held) -> Result<()>;
    fn remove(self, held: Self::Held) -> Result<()>;
}
// This exact dispatch path is shared by native capture and pure fault regressions.
fn dispatch<B: Backend>(mut backend: B) -> Result<()> {
    let held = backend.capture()?;
    validate(backend.expected(), held.observation())?;
    backend.emit(&held)?;
    backend.revalidate(&held)?;
    backend.remove(held)
}

pub(super) fn checked_remove(area: LinuxManagedArea, binding: [u8; 48]) -> Result<()> {
    let expected = Expected {
        identity: area.identity().to_bytes(),
        binding,
        // Numeric namespace-local ownership expectation comes from the caller,
        // independently of the RMA1 codec, which contains no owner fields.
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    };
    dispatch(capture::Native { area, expected })
}

const RECORD_MAX: usize = 32768;
struct BoundedRecord(Vec<u8>);
impl Write for BoundedRecord {
    fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        if bytes.len() > RECORD_MAX.saturating_sub(self.0.len()) {
            return Err(refuse());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
fn record(expected: &Expected, observed: &Observation) -> Result<Vec<u8>> {
    let mut out = BoundedRecord(Vec::new());
    out.write_all(b"F1_CLEANUP_V1 ")?;
    let value = serde_json::json!({
        "version": 1, "phase": "PRE_REMOVE", "identity_hex": hex(&expected.identity),
        "binding_hex": hex(&expected.binding), "name": observed.name,
        "boot_hex": hex(&observed.boot), "h": observed.h, "a": observed.a,
        "procs_hex": hex(observed.procs.as_ref().ok_or_else(refuse)?),
        "events_hex": hex(&observed.events), "events_eof": observed.events_eof, "procs_eof": observed.procs_eof,
        "inventory_eof": observed.inventory_eof, "inventory_bytes": observed.inventory_bytes,
        "inventory": observed.entries,
    });
    serde_json::to_writer(&mut out, &value).map_err(|_| refuse())?;
    out.write_all(b"\n")?;
    Ok(out.0)
}
fn emit_to(out: &mut impl Write, expected: &Expected, observed: &Observation) -> Result<()> {
    out.write_all(&record(expected, observed)?)?;
    out.flush()
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                DIGITS[(b >> 4) as usize] as char,
                DIGITS[(b & 15) as usize] as char,
            ]
        })
        .collect()
}
