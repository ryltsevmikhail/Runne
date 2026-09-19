use runne_daemon_native_effect::NativeAuthDescriptor;
use runne_provider_native_wire::NativeAccounting;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub(super) struct Spec {
    pub(super) provider_id: &'static str,
    pub(super) profile_id: &'static str,
    pub(super) model_id: &'static str,
    pub(super) profile_digest: [u8; 32],
    pub(super) pricing_digest: [u8; 32],
    pub(super) kind: WireKind,
    pub(super) auth: NativeAuthDescriptor,
    pub(super) endpoint: &'static str,
    pub(super) accounting: NativeAccounting,
    pub(super) max_output_tokens: u32,
    pub(super) context_window: u64,
}

#[derive(Clone, Copy)]
pub(super) enum WireKind {
    Anthropic,
    Gemini,
    Vertex,
}

pub(super) fn spec(profile_id: &str) -> Option<Spec> {
    let api = |value: &str| -> [u8; 32] { hex::decode(value).unwrap().try_into().unwrap() };
    let common = |provider_id,
                  profile_id,
                  model_id,
                  profile_digest,
                  pricing_digest,
                  kind,
                  auth,
                  endpoint,
                  accounting,
                  max_output_tokens,
                  context_window| Spec {
        provider_id,
        profile_id,
        model_id,
        profile_digest: api(profile_digest),
        pricing_digest: api(pricing_digest),
        kind,
        auth,
        endpoint,
        accounting,
        max_output_tokens,
        context_window,
    };
    match profile_id {
        runne_api::NATIVE_ANTHROPIC_PROFILE_ID => Some(common(
            "anthropic",
            runne_api::NATIVE_ANTHROPIC_PROFILE_ID,
            "claude-sonnet-4-6",
            "b09e56c7062c8947f94c3980b75654c82abf198d549813c3195dc7025c227566",
            "126eaf52c2f3bb65bdc0454ef9ffabdd551104617e4000390c20f8b79aa0929b",
            WireKind::Anthropic,
            NativeAuthDescriptor::AnthropicApiKey,
            "https://api.anthropic.com",
            NativeAccounting::Payg {
                input_micros_per_million: 3_000_000,
                output_micros_per_million: 15_000_000,
                cached_input_micros_per_million: 300_000,
                cache_write_micros_per_million: 3_750_000,
            },
            64_000,
            1_000_000,
        )),
        runne_api::NATIVE_GOOGLE_PROFILE_ID => Some(common(
            "google",
            runne_api::NATIVE_GOOGLE_PROFILE_ID,
            "gemini-2.5-flash",
            "d9a06ae2b3f3a81f8cac43d8cd6a1c3c0dceee916a27c6eafefc42c5e86fc313",
            "9c7afc394d0b08481bca3025b5a28b0858cb2247cca99d1a0080aba30a893e5d",
            WireKind::Gemini,
            NativeAuthDescriptor::GeminiApiKey,
            "https://generativelanguage.googleapis.com/v1beta",
            NativeAccounting::Payg {
                input_micros_per_million: 300_000,
                output_micros_per_million: 2_500_000,
                cached_input_micros_per_million: 30_000,
                cache_write_micros_per_million: 0,
            },
            65_536,
            1_048_576,
        )),
        runne_api::NATIVE_VERTEX_PROFILE_ID => Some(common(
            "google-vertex",
            runne_api::NATIVE_VERTEX_PROFILE_ID,
            "gemini-2.5-flash",
            "339699449efc6fbdda5e4841e2e87a21765cc244aa936f5cc076f8ff8cbad999",
            "ad0b16c2e50904841bea14e8faa9da9c302f31c4e26aedd5a5843a6f7c59bd6c",
            WireKind::Vertex,
            NativeAuthDescriptor::VertexBearer,
            "",
            NativeAccounting::Payg {
                input_micros_per_million: 300_000,
                output_micros_per_million: 2_500_000,
                cached_input_micros_per_million: 30_000,
                cache_write_micros_per_million: 0,
            },
            65_536,
            1_048_576,
        )),
        runne_api::NATIVE_KIMI_PROFILE_ID => Some(common(
            "kimi-coding",
            runne_api::NATIVE_KIMI_PROFILE_ID,
            "k3-256k",
            "14d2ec72a790983ca55bb8d75131da7cbfbb8f2598380fa47fdeac5e1655e1b0",
            "4dd94cb5be8efa2cab5a9aea39fb1e7d86669c46c648ae97879fe2a6728b32d2",
            WireKind::Anthropic,
            NativeAuthDescriptor::Bearer,
            "https://api.kimi.com/coding",
            NativeAccounting::SubscriptionQuotaExternallyMetered,
            131_072,
            262_144,
        )),
        runne_api::NATIVE_MINIMAX_PROFILE_ID => Some(minimax(
            runne_api::NATIVE_MINIMAX_PROFILE_ID,
            "minimax",
            "https://api.minimax.io/anthropic",
            "db0455e6fc68cb12286ab261d376a7ce2c95075261014f781ce119e2644ac19b",
            "2272d0757044ae411f6468ddbad798c406252d13e180bbe2aa9354c453d65e38",
        )),
        runne_api::NATIVE_MINIMAX_CN_PROFILE_ID => Some(minimax(
            runne_api::NATIVE_MINIMAX_CN_PROFILE_ID,
            "minimax-cn",
            "https://api.minimaxi.com/anthropic",
            "8edfe33db0345b34f206d251cdbd796f90ae2e2b5219ddf20a94180b5e131a0f",
            "189233517e530620b131289feea87136a3c685e274845ff7850d9248e1d79d29",
        )),
        runne_api::NATIVE_VERCEL_PROFILE_ID => Some(common(
            "vercel-ai-gateway",
            runne_api::NATIVE_VERCEL_PROFILE_ID,
            "openai/gpt-5.6-luna",
            "d9853c9e0ef9685759b45c4743e813f0755057223a68a371b987197edf52b576",
            "14b1c7963ce080d964239c950da9d1fd5eff37fa231fb56ffd39f0fe3c1ddff9",
            WireKind::Anthropic,
            NativeAuthDescriptor::Bearer,
            "https://ai-gateway.vercel.sh",
            NativeAccounting::Payg {
                input_micros_per_million: 200_000,
                output_micros_per_million: 1_200_000,
                cached_input_micros_per_million: 20_000,
                cache_write_micros_per_million: 250_000,
            },
            128_000,
            1_050_000,
        )),
        _ => None,
    }
}

fn minimax(
    profile_id: &'static str,
    provider_id: &'static str,
    endpoint: &'static str,
    profile_digest: &str,
    pricing_digest: &str,
) -> Spec {
    Spec {
        provider_id,
        profile_id,
        model_id: "MiniMax-M2.7",
        profile_digest: hex::decode(profile_digest).unwrap().try_into().unwrap(),
        pricing_digest: hex::decode(pricing_digest).unwrap().try_into().unwrap(),
        kind: WireKind::Anthropic,
        auth: NativeAuthDescriptor::AnthropicApiKey,
        endpoint,
        accounting: NativeAccounting::Payg {
            input_micros_per_million: 300_000,
            output_micros_per_million: 1_200_000,
            cached_input_micros_per_million: 60_000,
            cache_write_micros_per_million: 375_000,
        },
        max_output_tokens: 131_072,
        context_window: 204_800,
    }
}

pub(super) fn full_profile_digest(
    spec: Spec,
    endpoint: &str,
    accounting: NativeAccounting,
    limits: runne_provider_native_wire::WireLimits,
) -> [u8; 32] {
    let canonical = format!(
        "runne/native-profile/v2|{provider}|{profile}|{model}|{revision}|{endpoint}|{auth}|{context}|{entries}:{entry_bytes}:{bytes}:{tokens}:{output}:{request}:{frame}|{accounting}",
        provider = spec.provider_id,
        profile = spec.profile_id,
        model = spec.model_id,
        revision = super::REVISION,
        endpoint = endpoint,
        auth = auth_tag(spec.auth),
        context = spec.context_window,
        entries = limits.max_input_entries(),
        entry_bytes = limits.max_input_entry_bytes(),
        bytes = limits.max_input_bytes(),
        tokens = limits.max_input_tokens(),
        output = limits.max_output_tokens(),
        request = limits.max_request_bytes(),
        frame = limits.max_frame_bytes(),
        accounting = accounting_tag(accounting),
    );
    Sha256::digest(canonical.as_bytes()).into()
}

pub(super) fn pricing_digest(
    provider: &str,
    model: &str,
    accounting: NativeAccounting,
) -> [u8; 32] {
    let canonical = format!(
        "runne/native-pricing/v2|{provider}|{model}|{}",
        accounting_tag(accounting)
    );
    Sha256::digest(canonical.as_bytes()).into()
}

fn auth_tag(auth: NativeAuthDescriptor) -> &'static str {
    match auth {
        NativeAuthDescriptor::AnthropicApiKey => "anthropic_api_key",
        NativeAuthDescriptor::Bearer => "bearer",
        NativeAuthDescriptor::GeminiApiKey => "gemini_api_key",
        NativeAuthDescriptor::VertexBearer => "vertex_bearer",
    }
}

fn accounting_tag(accounting: NativeAccounting) -> String {
    match accounting {
        NativeAccounting::SubscriptionQuotaExternallyMetered => "subscription".to_owned(),
        NativeAccounting::TokenPlanQuotaExternallyMetered => "token_plan".to_owned(),
        NativeAccounting::ExternallyBilledUnpriced => "unpriced".to_owned(),
        NativeAccounting::Payg {
            input_micros_per_million,
            output_micros_per_million,
            cached_input_micros_per_million,
            cache_write_micros_per_million,
        } => format!(
            "payg:{input_micros_per_million}:{output_micros_per_million}:{cached_input_micros_per_million}:{cache_write_micros_per_million}"
        ),
    }
}
