use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};

fn strict_resume_request(body: &[u8]) -> Result<ResumeFromBaselineRequest, ReplayHttpFailure> {
    let mut decoder = serde_json::Deserializer::from_slice(body);
    StrictJson
        .deserialize(&mut decoder)
        .map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request"))?;
    decoder
        .end()
        .map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request"))?;
    serde_json::from_slice(body)
        .map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request"))
}

struct StrictJson;

impl<'de> DeserializeSeed<'de> for StrictJson {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("strict JSON")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> { Ok(()) }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> { Ok(()) }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> { Ok(()) }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> { Ok(()) }
    fn visit_str<E>(self, _: &str) -> Result<(), E> { Ok(()) }
    fn visit_string<E>(self, _: String) -> Result<(), E> { Ok(()) }
    fn visit_unit<E>(self) -> Result<(), E> { Ok(()) }

    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values.next_element_seed(StrictJson)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> Result<(), A::Error> {
        let mut names = HashSet::new();
        while let Some(name) = fields.next_key::<String>()? {
            if !names.insert(name) {
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            fields.next_value_seed(StrictJson)?;
        }
        Ok(())
    }
}
