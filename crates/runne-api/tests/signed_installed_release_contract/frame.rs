use std::io::{self, Cursor, Read};

use runne_api::{
    PendingSignedInstalledReleaseMetadataV2, SignedInstalledReleaseVerificationErrorV2 as Error,
    VerifiedSignedInstalledReleaseV2,
};
use runne_domain::DigestEqualityMatcherV1;

use super::canonical::fixture;

const MAGIC: &[u8; 8] = b"GCRMDV2\0";
const MAX_PAYLOAD_BYTES: u32 = 524_288;

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(12 + payload.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn read_error(bytes: &[u8]) -> Error {
    match PendingSignedInstalledReleaseMetadataV2::read_from(&mut Cursor::new(bytes)) {
        Ok(_) => panic!("invalid frame was accepted"),
        Err(error) => error,
    }
}

#[test]
fn frame_reads_one_canonical_payload_without_consuming_the_sentinel() {
    let mut bytes = framed(fixture());
    bytes.push(0xa5);
    let mut reader = Cursor::new(bytes);

    let _pending = PendingSignedInstalledReleaseMetadataV2::read_from(&mut reader)
        .expect("canonical release frame");

    assert_eq!(
        reader.position(),
        u64::try_from(12 + fixture().len()).unwrap()
    );
    let mut sentinel = [0_u8; 1];
    reader.read_exact(&mut sentinel).unwrap();
    assert_eq!(sentinel, [0xa5]);
}

#[test]
fn pending_frame_exposes_one_pinned_zero_clock_zero_trust_transition() {
    let verify: fn(
        PendingSignedInstalledReleaseMetadataV2,
        DigestEqualityMatcherV1,
    ) -> Result<VerifiedSignedInstalledReleaseV2, Error> =
        PendingSignedInstalledReleaseMetadataV2::verify_current_pinned;
    let _ = verify;
}

#[test]
fn frame_rejects_wrong_magic_and_little_endian_length() {
    let mut wrong_magic = framed(fixture());
    wrong_magic[6] = b'3';
    assert_eq!(read_error(&wrong_magic), Error::InvalidEncoding);

    let mut little_endian = Vec::new();
    little_endian.extend_from_slice(MAGIC);
    little_endian.extend_from_slice(&u32::try_from(fixture().len()).unwrap().to_le_bytes());
    assert_eq!(read_error(&little_endian), Error::MetadataTooLarge);
}

#[test]
fn frame_rejects_zero_and_oversize_lengths_before_payload_read() {
    let mut zero = MAGIC.to_vec();
    zero.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(read_error(&zero), Error::InvalidEncoding);

    let header = oversize_header(u32::MAX);
    let mut reader = HeaderOnlyReader::new(header);
    let error = match PendingSignedInstalledReleaseMetadataV2::read_from(&mut reader) {
        Ok(_) => panic!("oversize frame was accepted"),
        Err(error) => error,
    };
    assert_eq!(error, Error::MetadataTooLarge);
    assert_eq!(reader.bytes_read(), 12);

    let header = oversize_header(MAX_PAYLOAD_BYTES + 1);
    assert_eq!(read_error(&header), Error::MetadataTooLarge);
}

#[test]
fn frame_rejects_truncated_header_and_payload() {
    for truncated in [
        Vec::new(),
        MAGIC[..7].to_vec(),
        MAGIC.to_vec(),
        [MAGIC.as_slice(), &[0, 0, 0]].concat(),
        [MAGIC.as_slice(), &2_u32.to_be_bytes(), b"{"].concat(),
    ] {
        assert_eq!(read_error(&truncated), Error::InvalidEncoding);
    }
}

#[test]
fn frame_rejects_malformed_and_noncanonical_metadata() {
    assert_eq!(read_error(&framed(b"{")), Error::InvalidEncoding);

    let mut leading_space = vec![b' '];
    leading_space.extend_from_slice(fixture());
    let mut trailing_newline = fixture().to_vec();
    trailing_newline.push(b'\n');
    let reordered =
        serde_json::to_vec(&serde_json::from_slice::<serde_json::Value>(fixture()).unwrap())
            .unwrap();
    assert_ne!(reordered, fixture());
    for payload in [leading_space, trailing_newline, reordered] {
        assert_eq!(read_error(&framed(&payload)), Error::NonCanonicalMetadata);
    }
}

fn oversize_header(length: u32) -> [u8; 12] {
    let mut header = [0_u8; 12];
    header[..8].copy_from_slice(MAGIC);
    header[8..].copy_from_slice(&length.to_be_bytes());
    header
}

struct HeaderOnlyReader {
    header: Cursor<[u8; 12]>,
}

impl HeaderOnlyReader {
    fn new(header: [u8; 12]) -> Self {
        Self {
            header: Cursor::new(header),
        }
    }

    fn bytes_read(&self) -> u64 {
        self.header.position()
    }
}

impl Read for HeaderOnlyReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        assert!(
            self.header.position() < 12,
            "payload read after invalid length"
        );
        self.header.read(buffer)
    }
}
