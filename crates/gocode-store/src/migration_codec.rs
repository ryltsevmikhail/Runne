//! Versioned canonical codecs for migration control-plane artifacts.

use core::fmt;

use gocode_application::migration::types::{
    ArtifactDigest, CohortDimension, CohortSelector, FencingToken, MigrationValueError,
    RollbackDisposition, RoutingGeneration, RoutingSnapshot, RuntimeAuthority,
    RuntimeGenerationRef,
};
use gocode_domain::timestamp::Timestamp;

const CODEC_VERSION: u8 = 1;

/// Fail-closed migration codec errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationCodecError {
    /// Unsupported leading codec version.
    UnknownVersion {
        /// Version read from durable bytes.
        actual: u8,
    },
    /// Closed enum tag is unknown.
    UnknownTag {
        /// Field whose tag was invalid.
        field: &'static str,
        /// Unknown tag.
        actual: u8,
    },
    /// Durable bytes ended before the value was complete.
    Truncated,
    /// Bytes remained after one canonical value.
    TrailingBytes {
        /// Number of bytes not consumed.
        remaining: usize,
    },
    /// A length-prefixed value exceeds its bound.
    Oversized {
        /// Field whose value was oversized.
        field: &'static str,
        /// Maximum number of bytes.
        max: usize,
        /// Actual number of bytes.
        actual: usize,
    },
    /// A string is not valid UTF-8.
    InvalidUtf8 {
        /// Field containing invalid UTF-8.
        field: &'static str,
    },
    /// Decoded values violate the application value contract.
    InvalidValue {
        /// Field whose value is invalid.
        field: &'static str,
    },
}

impl fmt::Display for MigrationCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for MigrationCodecError {}

/// Encode one routing snapshot using migration codec version 1.
pub fn encode_routing_snapshot(snapshot: &RoutingSnapshot) -> Result<Vec<u8>, MigrationCodecError> {
    let mut bytes = Vec::with_capacity(256);
    bytes.push(CODEC_VERSION);
    bytes.extend_from_slice(&snapshot.routing_generation.get().to_be_bytes());
    write_string(&mut bytes, "source", snapshot.source.as_str())?;
    write_string(&mut bytes, "candidate", snapshot.candidate.as_str())?;
    let dimension_count = u16::try_from(snapshot.cohort.dimensions().len()).map_err(|_| {
        MigrationCodecError::Oversized {
            field: "cohort",
            max: usize::from(u16::MAX),
            actual: snapshot.cohort.dimensions().len(),
        }
    })?;
    bytes.extend_from_slice(&dimension_count.to_be_bytes());
    for dimension in snapshot.cohort.dimensions() {
        write_string(&mut bytes, "cohort_key", dimension.key())?;
        write_string(&mut bytes, "cohort_value", dimension.value())?;
    }
    match &snapshot.authority {
        RuntimeAuthority::Source(generation) => {
            bytes.push(1);
            write_string(&mut bytes, "authority_generation", generation.as_str())?;
        }
        RuntimeAuthority::Candidate(generation) => {
            bytes.push(2);
            write_string(&mut bytes, "authority_generation", generation.as_str())?;
        }
    }
    bytes.extend_from_slice(snapshot.contract_digest.as_bytes());
    bytes.extend_from_slice(snapshot.profile_digest.as_bytes());
    bytes.extend_from_slice(snapshot.config_digest.as_bytes());
    bytes.extend_from_slice(snapshot.fencing_token.as_bytes());
    bytes.push(match snapshot.rollback_disposition {
        RollbackDisposition::Eligible => 1,
        RollbackDisposition::Ineligible => 2,
    });
    bytes.extend_from_slice(&snapshot.committed_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Decode one canonical routing snapshot.
pub fn decode_routing_snapshot(bytes: &[u8]) -> Result<RoutingSnapshot, MigrationCodecError> {
    let mut decoder = Decoder::new(bytes);
    let version = decoder.read_u8()?;
    if version != CODEC_VERSION {
        return Err(MigrationCodecError::UnknownVersion { actual: version });
    }
    let routing_generation = RoutingGeneration::new(decoder.read_u64()?).map_err(|_| {
        MigrationCodecError::InvalidValue {
            field: "routing_generation",
        }
    })?;
    let source = runtime_generation(decoder.read_string("source")?, "source")?;
    let candidate = runtime_generation(decoder.read_string("candidate")?, "candidate")?;
    if source == candidate {
        return Err(MigrationCodecError::InvalidValue {
            field: "source_candidate",
        });
    }
    let dimension_count = usize::from(decoder.read_u16()?);
    let mut dimensions = Vec::with_capacity(dimension_count);
    for _ in 0..dimension_count {
        dimensions.push(
            CohortDimension::new(
                decoder.read_string("cohort_key")?,
                decoder.read_string("cohort_value")?,
            )
            .map_err(|_| MigrationCodecError::InvalidValue { field: "cohort" })?,
        );
    }
    let cohort = CohortSelector::new(dimensions)
        .map_err(|_| MigrationCodecError::InvalidValue { field: "cohort" })?;
    let authority_tag = decoder.read_u8()?;
    let authority_generation = runtime_generation(
        decoder.read_string("authority_generation")?,
        "authority_generation",
    )?;
    let authority = match authority_tag {
        1 if authority_generation == source => RuntimeAuthority::Source(authority_generation),
        2 if authority_generation == candidate => RuntimeAuthority::Candidate(authority_generation),
        1 | 2 => {
            return Err(MigrationCodecError::InvalidValue {
                field: "authority_generation",
            });
        }
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "authority",
                actual,
            });
        }
    };
    let contract_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let profile_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let config_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let fencing_token = FencingToken::new(decoder.read_array()?).map_err(|_| {
        MigrationCodecError::InvalidValue {
            field: "fencing_token",
        }
    })?;
    let rollback_disposition = match decoder.read_u8()? {
        1 => RollbackDisposition::Eligible,
        2 => RollbackDisposition::Ineligible,
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "rollback_disposition",
                actual,
            });
        }
    };
    let committed_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    decoder.finish()?;

    Ok(RoutingSnapshot {
        routing_generation,
        source,
        candidate,
        cohort,
        authority,
        contract_digest,
        profile_digest,
        config_digest,
        fencing_token,
        rollback_disposition,
        committed_at,
    })
}

fn write_string(
    output: &mut Vec<u8>,
    field: &'static str,
    value: &str,
) -> Result<(), MigrationCodecError> {
    let length = u16::try_from(value.len()).map_err(|_| MigrationCodecError::Oversized {
        field,
        max: usize::from(u16::MAX),
        actual: value.len(),
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn runtime_generation(
    value: String,
    field: &'static str,
) -> Result<RuntimeGenerationRef, MigrationCodecError> {
    RuntimeGenerationRef::new(value).map_err(|error| match error {
        MigrationValueError::TooLong { max, actual, .. } => {
            MigrationCodecError::Oversized { field, max, actual }
        }
        _ => MigrationCodecError::InvalidValue { field },
    })
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, MigrationCodecError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(MigrationCodecError::Truncated)?;
        self.position += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, MigrationCodecError> {
        Ok(u16::from_be_bytes(self.read_exact::<2>()?))
    }

    fn read_u64(&mut self) -> Result<u64, MigrationCodecError> {
        Ok(u64::from_be_bytes(self.read_exact::<8>()?))
    }

    fn read_i64(&mut self) -> Result<i64, MigrationCodecError> {
        Ok(i64::from_be_bytes(self.read_exact::<8>()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], MigrationCodecError> {
        self.read_exact::<N>()
    }

    fn read_string(&mut self, field: &'static str) -> Result<String, MigrationCodecError> {
        let length = usize::from(self.read_u16()?);
        let end = self
            .position
            .checked_add(length)
            .ok_or(MigrationCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MigrationCodecError::Truncated)?;
        self.position = end;
        String::from_utf8(value.to_vec()).map_err(|_| MigrationCodecError::InvalidUtf8 { field })
    }

    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], MigrationCodecError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(MigrationCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MigrationCodecError::Truncated)?;
        let mut output = [0; N];
        output.copy_from_slice(value);
        self.position = end;
        Ok(output)
    }

    fn finish(self) -> Result<(), MigrationCodecError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(MigrationCodecError::TrailingBytes {
                remaining: self.bytes.len() - self.position,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use gocode_application::migration::types::{
        ArtifactDigest, CohortDimension, CohortSelector, FencingToken, RollbackDisposition,
        RoutingGeneration, RoutingSnapshot, RuntimeAuthority, RuntimeGenerationRef,
    };
    use gocode_domain::timestamp::Timestamp;

    use super::*;

    const GOLDEN_ROUTING_SNAPSHOT_HEX: &str = concat!(
        "010000000000000002",
        "000e72756e74696d652d6c6567616379",
        "000e72756e74696d652d6e6174697665",
        "0001",
        "000c636c69656e745f636c617373",
        "00077072656d69756d",
        "02",
        "000e72756e74696d652d6e6174697665",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0404040404040404040404040404040404040404040404040404040404040404",
        "0707070707070707070707070707070707070707070707070707070707070707",
        "01",
        "000000000000000a"
    );

    #[test]
    fn routing_snapshot_codec_has_literal_golden_bytes() {
        let bytes = encode_routing_snapshot(&golden_snapshot()).unwrap();

        assert_eq!(hex(&bytes), GOLDEN_ROUTING_SNAPSHOT_HEX);
        assert_eq!(decode_routing_snapshot(&bytes).unwrap(), golden_snapshot());
    }

    #[test]
    fn migration_codec_rejects_unknown_version_and_trailing_bytes() {
        assert_eq!(
            decode_routing_snapshot(&[0xff]),
            Err(MigrationCodecError::UnknownVersion { actual: 255 })
        );

        let mut bytes = encode_routing_snapshot(&golden_snapshot()).unwrap();
        bytes.push(0);
        assert_eq!(
            decode_routing_snapshot(&bytes),
            Err(MigrationCodecError::TrailingBytes { remaining: 1 })
        );
    }

    fn golden_snapshot() -> RoutingSnapshot {
        let source = RuntimeGenerationRef::new("runtime-legacy").unwrap();
        let candidate = RuntimeGenerationRef::new("runtime-native").unwrap();
        RoutingSnapshot {
            routing_generation: RoutingGeneration::new(2).unwrap(),
            source,
            candidate: candidate.clone(),
            cohort: CohortSelector::new(vec![
                CohortDimension::new("client_class", "premium").unwrap(),
            ])
            .unwrap(),
            authority: RuntimeAuthority::Candidate(candidate),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            profile_digest: ArtifactDigest::from_bytes([1; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
            fencing_token: FencingToken::new([7; 32]).unwrap(),
            rollback_disposition: RollbackDisposition::Eligible,
            committed_at: Timestamp::from_unix_micros(10),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
}
