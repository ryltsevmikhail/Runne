use super::{NOW, expected, signed_pair, verifier};
use crate::{QualificationFaultSelector, QualificationProcessRole};
use serde_json::{Value, json};

fn writer(value: &mut Value) {
    value["selector"] = json!("kill_writer_process");
    value["process_role"] = json!("writer");
}

#[test]
fn writer_combined_verification_returns_only_writer_local_capability() {
    let fault = verifier()
        .verify_exact_writer_fault_borrowed(
            &signed_pair(writer, writer),
            expected().candidate,
            expected().raw_tuple,
            NOW,
        )
        .expect("independently signed Writer pair");
    assert_eq!(fault.process_role(), QualificationProcessRole::Writer);
    assert_eq!(fault.selector(), QualificationFaultSelector::WriterProcess);
    assert_eq!(fault.ticket_id(), [0x11; 32]);
}

#[test]
fn writer_combined_verification_rejects_foreign_roles_and_installed_facts() {
    for (pair, candidate, tuple, now) in [
        (
            signed_pair(|_| {}, |_| {}),
            expected().candidate,
            expected().raw_tuple,
            NOW,
        ),
        (
            signed_pair(writer, writer),
            [0xab; 32],
            expected().raw_tuple,
            NOW,
        ),
        (
            signed_pair(writer, writer),
            expected().candidate,
            [0xee; 32],
            NOW,
        ),
        (
            signed_pair(writer, writer),
            expected().candidate,
            expected().raw_tuple,
            NOW + 300,
        ),
    ] {
        let result = verifier().verify_exact_writer_fault_borrowed(&pair, candidate, tuple, now);
        assert!(result.is_err());
    }
}

#[test]
fn writer_combined_verification_consumes_replay_state() {
    let mut verifier = verifier();
    for succeeds in [true, false] {
        let pair = signed_pair(writer, writer);
        let result = verifier.verify_exact_writer_fault_borrowed(
            &pair,
            expected().candidate,
            expected().raw_tuple,
            NOW,
        );
        let success = result.is_ok();
        assert_eq!(success, succeeds);
    }
}
