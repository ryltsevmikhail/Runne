//! Duplicate-safe JSON parser used only by neutral stage contract validation.
use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::{collections::BTreeSet, fmt};

pub fn parse(bytes: &[u8]) -> Result<Value, ()> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut decoder).map_err(|_| ())?;
    decoder.end().map_err(|_| ())?;
    Ok(value)
}
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(VisitorImpl)
    }
}
struct VisitorImpl;
impl<'de> Visitor<'de> for VisitorImpl {
    type Value = Strict;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict JSON")
    }
    fn visit_bool<E>(self, x: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(x)))
    }
    fn visit_i64<E>(self, x: i64) -> Result<Strict, E> {
        Ok(Strict(Value::Number(x.into())))
    }
    fn visit_u64<E>(self, x: u64) -> Result<Strict, E> {
        Ok(Strict(Value::Number(x.into())))
    }
    fn visit_f64<E: serde::de::Error>(self, x: f64) -> Result<Strict, E> {
        serde_json::Number::from_f64(x)
            .map(|n| Strict(Value::Number(n)))
            .ok_or_else(|| E::custom("number"))
    }
    fn visit_str<E>(self, x: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(x.into())))
    }
    fn visit_string<E>(self, x: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(x)))
    }
    fn visit_none<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
        let mut x = Vec::new();
        while let Some(Strict(v)) = a.next_element()? {
            x.push(v);
        }
        Ok(Strict(Value::Array(x)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
        let mut seen = BTreeSet::new();
        let mut out = Map::new();
        while let Some((k, Strict(v))) = a.next_entry::<String, Strict>()? {
            if !seen.insert(k.clone()) {
                return Err(A::Error::custom("duplicate"));
            }
            out.insert(k, v);
        }
        Ok(Strict(Value::Object(out)))
    }
}
