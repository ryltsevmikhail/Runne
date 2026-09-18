/// Exact daemon provider activation mode.
pub const NATIVE_ANTHROPIC_PROFILE_ID: &str = "gocode-native/anthropic/claude-sonnet-4-6/1";
pub const NATIVE_GOOGLE_PROFILE_ID: &str = "gocode-native/google/gemini-2.5-flash/1";
pub const NATIVE_VERTEX_PROFILE_ID: &str = "gocode-native/google-vertex/gemini-2.5-flash/1";
pub const NATIVE_KIMI_PROFILE_ID: &str = "gocode-native/kimi-coding/k3-256k/1";
pub const NATIVE_MINIMAX_PROFILE_ID: &str = "gocode-native/minimax/MiniMax-M2.7/1";
pub const NATIVE_MINIMAX_CN_PROFILE_ID: &str = "gocode-native/minimax-cn/MiniMax-M2.7/1";
pub const NATIVE_VERCEL_PROFILE_ID: &str = "gocode-native/vercel-ai-gateway/openai-gpt-5.6-luna/1";
pub const RADIUS_TEXT_PROFILE_ID: &str = "gocode-radius-text/dynamic/1";

pub const NATIVE_ANTHROPIC_PROFILE_DIGEST: [u8; 32] =
    hex_digest("b09e56c7062c8947f94c3980b75654c82abf198d549813c3195dc7025c227566");
pub const NATIVE_GOOGLE_PROFILE_DIGEST: [u8; 32] =
    hex_digest("d9a06ae2b3f3a81f8cac43d8cd6a1c3c0dceee916a27c6eafefc42c5e86fc313");
pub const NATIVE_VERTEX_PROFILE_DIGEST: [u8; 32] =
    hex_digest("339699449efc6fbdda5e4841e2e87a21765cc244aa936f5cc076f8ff8cbad999");
pub const NATIVE_KIMI_PROFILE_DIGEST: [u8; 32] =
    hex_digest("14d2ec72a790983ca55bb8d75131da7cbfbb8f2598380fa47fdeac5e1655e1b0");
pub const NATIVE_MINIMAX_PROFILE_DIGEST: [u8; 32] =
    hex_digest("db0455e6fc68cb12286ab261d376a7ce2c95075261014f781ce119e2644ac19b");
pub const NATIVE_MINIMAX_CN_PROFILE_DIGEST: [u8; 32] =
    hex_digest("8edfe33db0345b34f206d251cdbd796f90ae2e2b5219ddf20a94180b5e131a0f");
pub const NATIVE_VERCEL_PROFILE_DIGEST: [u8; 32] =
    hex_digest("d9853c9e0ef9685759b45c4743e813f0755057223a68a371b987197edf52b576");

const fn hex_value(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => 0,
    }
}

const fn hex_digest(value: &str) -> [u8; 32] {
    let bytes = value.as_bytes();
    let mut output = [0; 32];
    let mut index = 0;
    while index < 32 {
        output[index] = (hex_value(bytes[index * 2]) << 4) | hex_value(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}
