/// L3 fixture validator.
pub struct L3FixtureStore;

#[derive(Clone, Debug)]
pub struct SanitizedFixture {
    pub fixture_id: String,
    pub fixture_digest: VerificationDigest,
    pub schema_revision: String,
    pub collection_time: String,
    pub rights_metadata: String,
    pub sanitization_passed: bool,
}

impl L3FixtureStore {
    pub fn validate_and_store(
        fixture: &SanitizedFixture,
        authorized: bool,
    ) -> Result<String, String> {
        if !authorized {
            return Err("missing authorization".into());
        }
        if !fixture.sanitization_passed {
            return Err("sanitization incomplete".into());
        }
        if fixture.rights_metadata.contains("production") {
            return Err("production traffic prohibited".into());
        }
        Ok(format!("fixture:{}", fixture.fixture_id))
    }
}
