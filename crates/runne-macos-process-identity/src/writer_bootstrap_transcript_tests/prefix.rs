use std::io::{Cursor, Read as _};

use super::super::read_prefix;
use super::support::PrefixFixture;

#[test]
fn fixed_prefix_is_read_only_in_attestation_ticket_release_order() {
    let fixture = PrefixFixture::new();
    let prefix = fixture.prefix();
    let mut reader = Cursor::new(&prefix);
    let _ = read_prefix(&mut reader, fixture.public_key).expect("exact prefix");
    assert_eq!(reader.position(), u64::try_from(prefix.len()).unwrap());

    for swapped in [
        [
            fixture.ticket.as_slice(),
            fixture.attestation.as_slice(),
            fixture.release.as_slice(),
        ]
        .concat(),
        [
            fixture.attestation.as_slice(),
            fixture.release.as_slice(),
            fixture.ticket.as_slice(),
        ]
        .concat(),
    ] {
        assert!(read_prefix(&mut Cursor::new(swapped), fixture.public_key).is_err());
    }
}

#[test]
fn fixed_prefix_reads_exactly_one_issue_ticket() {
    let fixture = PrefixFixture::new();
    let prefix = fixture.prefix();
    let mut bytes = prefix.clone();
    bytes.extend_from_slice(&fixture.ticket);
    let mut reader = Cursor::new(bytes);

    let _ = read_prefix(&mut reader, fixture.public_key).expect("exact prefix");

    assert_eq!(reader.position(), u64::try_from(prefix.len()).unwrap());
    let mut next_ticket = vec![0_u8; fixture.ticket.len()];
    reader.read_exact(&mut next_ticket).unwrap();
    assert_eq!(next_ticket, fixture.ticket);
}
