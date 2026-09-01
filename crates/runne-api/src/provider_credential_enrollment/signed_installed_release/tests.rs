#[path = "tests/known_answers.rs"]
mod known_answers;
#[path = "tests/release_binding_rejections.rs"]
mod release_binding_rejections;
#[path = "tests/release_rejections.rs"]
mod release_rejections;
#[path = "tests/role_rejections.rs"]
mod role_rejections;
#[path = "tests/trust_rejections.rs"]
mod trust_rejections;

impl super::tuple::NativeEnrollmentTupleV2 {
    fn test_only_rebind_digest(&mut self, target: &super::model::UpdateTargetV2) {
        self.tuple_sha256 = self.digest_for(target);
    }
}
