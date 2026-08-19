use async_trait::async_trait;
use runne_domain::verification::backup::PromotionPolicy;
use runne_domain::verification::identity::*;

pub enum PromotionResult {
    Promoted { promotion_id: PromotionID },
    Blocked { reason: String },
}

#[async_trait]
pub trait PromotionManager: Send + Sync {
    async fn promote(
        &self,
        policy: &PromotionPolicy,
        intent_id: IntentID,
        idemp_key: &str,
        dispatch_key: &str,
    ) -> Result<PromotionResult, String>;
}
