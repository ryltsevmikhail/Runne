//! Object-only serde adapter; delegates to INNER wire type, never itself.
use serde::de::{MapAccess, Visitor, value::MapAccessDeserializer};
use serde::{Deserialize, Deserializer};
use std::{fmt, marker::PhantomData};
pub(super) struct MapOnly<T>(pub(super) T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(MapOnlyVisitor(PhantomData))
    }
}
struct MapOnlyVisitor<T>(PhantomData<T>);
impl<'de, T: Deserialize<'de>> Visitor<'de> for MapOnlyVisitor<T> {
    type Value = MapOnly<T>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object")
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        T::deserialize(MapAccessDeserializer::new(map)).map(MapOnly)
    }
}
