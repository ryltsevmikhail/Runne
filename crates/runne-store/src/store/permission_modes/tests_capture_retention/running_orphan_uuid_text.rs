//! Explicit serde adapter: no dependence on the uuid crate's serde feature.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

pub(super) fn serialize<S: Serializer>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
    value.to_string().serialize(serializer)
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
    let text = String::deserialize(deserializer)?;
    let value = Uuid::parse_str(&text).map_err(serde::de::Error::custom)?;
    if value.to_string() != text {
        return Err(serde::de::Error::custom(
            "canonical scenario UUID text required",
        ));
    }
    Ok(value)
}
