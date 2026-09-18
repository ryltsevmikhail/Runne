use super::*;

pub(super) fn descriptor(provider: ProviderCredentialProviderV2) -> Option<QuotaRequestDescriptor> {
    Some(match provider {
        ProviderCredentialProviderV2::Zai => QuotaRequestDescriptor::zai_global(),
        ProviderCredentialProviderV2::ZaiCodingCn => QuotaRequestDescriptor::zai_china(),
        ProviderCredentialProviderV2::KimiCoding => QuotaRequestDescriptor::kimi_coding(),
        ProviderCredentialProviderV2::MiniMax => QuotaRequestDescriptor::minimax(),
        ProviderCredentialProviderV2::MiniMaxCn => QuotaRequestDescriptor::minimax_china(),
        ProviderCredentialProviderV2::QwenTokenPlanIndividual => {
            QuotaRequestDescriptor::qwen_token_plan_individual()
        }
        _ => return None,
    })
}

pub(super) fn observation_id()
-> Result<CredentialOperationId, ProviderCredentialEnrollmentHostError> {
    let mut bytes = [0_u8; 16];
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut bytes)
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
    CredentialOperationId::from_bytes(bytes)
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
}

pub(super) fn high_water_seconds(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(1).max(1)
}
