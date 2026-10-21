use super::*;
use super::{
    map_only::MapOnly,
    storage::{PackageWire, ProfileWire},
};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use std::fmt;
enum KindWire {
    Mcp,
    Plugin,
}
enum TransportWire {
    LocalContained,
    RemoteBrokered,
}
// Unit enum derives also accept {"variant":null}; wire values are closed STRINGS.
impl<'de> Deserialize<'de> for KindWire {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match String::deserialize(d)?.as_str() {
            "mcp" => Ok(Self::Mcp),
            "plugin" => Ok(Self::Plugin),
            _ => Err(de::Error::custom("invalid kind")),
        }
    }
}
impl<'de> Deserialize<'de> for TransportWire {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match String::deserialize(d)?.as_str() {
            "local_contained" => Ok(Self::LocalContained),
            "remote_brokered" => Ok(Self::RemoteBrokered),
            _ => Err(de::Error::custom("invalid transport")),
        }
    }
}
pub(super) struct RecordWire {
    kind: KindWire,
    id: String,
    record_revision: u64,
    transport: Option<TransportWire>,
    required_profile: Option<MapOnly<ProfileWire>>,
    package: Option<MapOnly<PackageWire>>,
}
impl<'de> Deserialize<'de> for RecordWire {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(RecordVisitor)
    }
}
struct RecordVisitor;
impl<'de> Visitor<'de> for RecordVisitor {
    type Value = RecordWire;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a registration object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let (mut kind, mut id, mut revision, mut transport, mut profile, mut package) =
            (None, None, None, None, None, None);
        let mut seen = 0u8;
        while let Some(key) = map.next_key::<String>()? {
            let bit = match key.as_str() {
                "kind" => 1,
                "id" => 2,
                "record_revision" => 4,
                "transport" => 8,
                "required_profile" => 16,
                "package" => 32,
                _ => return Err(de::Error::custom("unknown field")),
            };
            if seen & bit != 0 {
                return Err(de::Error::custom("duplicate field"));
            }
            seen |= bit;
            match bit {
                1 => kind = Some(map.next_value()?),
                2 => id = Some(map.next_value()?),
                4 => revision = Some(map.next_value()?),
                8 => transport = Some(map.next_value()?),
                16 => profile = Some(map.next_value()?),
                32 => package = Some(map.next_value()?),
                _ => unreachable!(),
            }
        }
        let kind = kind.ok_or_else(|| de::Error::missing_field("kind"))?;
        let required = match kind {
            KindWire::Mcp => 31,
            KindWire::Plugin => 39,
        };
        if seen != required {
            return Err(de::Error::custom("invalid field set"));
        }
        Ok(RecordWire {
            kind,
            id: id.ok_or_else(|| de::Error::missing_field("id"))?,
            record_revision: revision.ok_or_else(|| de::Error::missing_field("record_revision"))?,
            transport,
            required_profile: profile,
            package,
        })
    }
}
impl RecordWire {
    pub(super) fn normalize(self) -> Result<ConfiguredMetadata, MetadataQueryError> {
        let invalid = MetadataQueryError::InvalidSnapshot;
        if !valid_id(&self.id) || !bounded_revision(self.record_revision) {
            return Err(invalid);
        }
        let id = RegistrationId(self.id);
        let record_revision = self.record_revision;
        Ok(match self.kind {
            KindWire::Mcp => {
                let p = self.required_profile.ok_or(invalid)?.0;
                if !valid_id(&p.id) || !bounded_revision(p.revision) {
                    return Err(invalid);
                }
                let transport = match self.transport.ok_or(invalid)? {
                    TransportWire::LocalContained => TransportClass::LocalContained,
                    TransportWire::RemoteBrokered => TransportClass::RemoteBrokered,
                };
                ConfiguredMetadata::Mcp {
                    id,
                    record_revision,
                    transport,
                    required_profile: RequiredMcpProfile {
                        id: ProfileId(p.id),
                        revision: p.revision,
                    },
                    availability: record::mcp_availability(runne_mcp::PRODUCTION_MCP_SDK_ENABLED)?,
                }
            }
            KindWire::Plugin => {
                let p = self.package.ok_or(invalid)?.0;
                if !valid_semver(&p.version) {
                    return Err(invalid);
                }
                ConfiguredMetadata::Plugin {
                    id,
                    record_revision,
                    package: DeclaredPackage {
                        version: PackageVersion(p.version),
                        digest: decode_hex(&p.digest)?,
                    },
                    availability: PluginAvailability::ActivationNotIntegrated,
                }
            }
        })
    }
}
