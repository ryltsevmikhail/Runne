"""Exact Linux lifetime seams for the provider-credential surface validator."""

from __future__ import annotations

import re
from collections.abc import Callable


def validate_linux_lifetime(
    validator: object,
    brace_body: Callable[[str, str], str | None],
) -> None:
    response_path = "crates/runne-platform-desktop/src/provider_credential_prompt/linux_gui_response.rs"
    response = validator.require(
        response_path,
        "LINUX_PROMPT_RESPONSE_OWNER",
        "let mut response = Zeroizing::new(Vec::with_capacity(maximum));",
        "let mut chunk = Zeroizing::new([0_u8; READ_CHUNK_BYTES]);",
        "maximum.saturating_sub(response.len())",
        "response.extend_from_slice(&chunk[..read]);",
        "fn wait_readable(",
        "saturating_duration_since(Instant::now())",
        "poll(",
    )
    read_body = brace_body(response, "pub(super) fn read_bounded_response(")
    if read_body is None or read_body.find("maximum.saturating_sub(response.len())") > read_body.find(
        "response.extend_from_slice(&chunk[..read]);"
    ):
        validator.fail("LINUX_PROMPT_RESPONSE_OWNER", response_path, "response append must follow the fixed-bound check")
    if re.search(
        r"let mut (?:response|chunk)\s*=\s*(?:Vec::new\(\)|\[0_u8;)",
        read_body or "",
    ):
        validator.fail("LINUX_PROMPT_RESPONSE_OWNER", response_path, "prompt response and scratch must be zeroizing owners")

    prompt_path = "crates/runne-platform-desktop/src/provider_credential_prompt/linux_gui.rs"
    prompt = validator.require(
        prompt_path,
        "LINUX_PROMPT_READER_TERMINAL",
        "MAX_RESPONSE_BYTES: usize = 3 * MAX_NATIVE_OAUTH_CREDENTIAL_BYTES + 256",
    )
    prompt_body = brace_body(prompt, "pub fn prompt_with_env(")
    prompt_anchors = (
        "stdout.as_fd().try_clone_to_owned()",
        "let reader_thread = thread::spawn(move ||",
        "wait_readable(poll_fd.as_fd(), deadline)",
        "receiver.recv_timeout(remaining)",
    )
    if prompt_body is None or any(anchor not in prompt_body for anchor in prompt_anchors):
        validator.fail("LINUX_PROMPT_READER_TERMINAL", prompt_path, "prompt must use a deadline-bound reader")
    if prompt_body is None or prompt_body.count("reader_thread.join()") != 2:
        validator.fail("LINUX_PROMPT_READER_TERMINAL", prompt_path, "all prompt reader terminal branches must join")
    if "read_to_end" in prompt:
        validator.fail("LINUX_PROMPT_READER_TERMINAL", prompt_path, "prompt response must use the bounded deadline reader")

    crypto_path = "crates/runne-secure-store/src/keyring/linux_secret_service/dh_session.rs"
    crypto = validator.require(
        crypto_path,
        "LINUX_SECRET_SERVICE_ZEROIZING_CRYPTO",
        "const MAX_CIPHERTEXT_BYTES: usize =",
        "(MAX_ENCODED_PROVIDER_CREDENTIAL_BYTES / AES_BLOCK_BYTES + 1) * AES_BLOCK_BYTES;",
        "let mut output = Zeroizing::new(vec![0; capacity]);",
        "encrypt_padded_b2b_mut::<Pkcs7>(data, &mut output)",
        "let mut plaintext = Zeroizing::new(data.to_vec());",
        "data.len() > MAX_CIPHERTEXT_BYTES",
        "decrypt_padded_in_place(&mut plaintext, key, iv)?",
        "fn decrypt_padded_in_place(",
        "buffer: &mut Zeroizing<Vec<u8>>",
        "decrypt_padded_mut::<Pkcs7>(buffer)",
        "buffer.zeroize();",
        "buffer[plaintext_len..].zeroize();",
        "fn generate_private_key() -> Zeroizing<[u8; 128]>",
        "let private = generate_private_key();",
        "let shared_bytes = Zeroizing::new(shared.to_bytes_be());",
        "let mut ikm = Zeroizing::new([0_u8; DH_PRIME.len()]);",
        "let mut okm = Zeroizing::new([0_u8; 16]);",
        ") -> Result<Zeroizing<[u8; 16]>, SsBusError> {",
        "prk.zeroize();",
    )
    encrypt_body = brace_body(crypto, "pub fn encrypt_with_iv(")
    decrypt_body = brace_body(crypto, "pub fn decrypt_with_iv(")
    in_place_body = brace_body(crypto, "fn decrypt_padded_in_place(")
    decrypt_limit = decrypt_body.find("data.len() > MAX_CIPHERTEXT_BYTES") if decrypt_body else -1
    decrypt_copy = decrypt_body.find("let mut plaintext = Zeroizing::new(data.to_vec());") if decrypt_body else -1
    if decrypt_limit < 0 or decrypt_copy < 0 or decrypt_limit > decrypt_copy:
        validator.fail("LINUX_SECRET_SERVICE_ZEROIZING_CRYPTO", crypto_path, "ciphertext bound must be checked before the Rust copy")
    derive_body = brace_body(crypto, "fn derive_shared_key_zeroizing(")
    ordinary_key_buffer = derive_body is None or any(
        (assignment := re.search(rf"let\s+(?:mut\s+)?{name}\s*=\s*([^;\n]+)", derive_body))
        and not assignment.group(1).startswith("Zeroizing::new(")
        for name in ("shared_bytes", "ikm", "okm")
    )
    if ordinary_key_buffer:
        validator.fail("LINUX_SECRET_SERVICE_ZEROIZING_CRYPTO", crypto_path, "repository-owned DH key-derivation buffers must be zeroizing")
    if any(
        body is not None and re.search(r"(?:encrypt|decrypt)_padded_vec_mut", body)
        for body in (encrypt_body, decrypt_body, in_place_body)
    ):
        validator.fail("LINUX_SECRET_SERVICE_ZEROIZING_CRYPTO", crypto_path, "padded_vec_mut creates an unzeroized plaintext scratch")

    layout_path = "crates/runne-secure-store/src/provider_credential/codec_layout.rs"
    validator.require(
        layout_path,
        "LINUX_SECRET_SERVICE_ZEROIZING_CRYPTO",
        "MAX_ENCODED_PROVIDER_CREDENTIAL_BYTES: usize =",
        "PROVIDER_CREDENTIAL_HEADER_BYTES",
        "+ PROVIDER_CREDENTIAL_REVISION_BYTES",
        "+ MAX_NATIVE_OAUTH_CREDENTIAL_BYTES;",
    )

    cache_path = "crates/runne-secure-store/src/keyring/linux_secret_service/cache.rs"
    cache = validator.require(
        cache_path,
        "LINUX_KEYUTILS_ZEROIZING_READ",
    )
    get_body = brace_body(
        cache,
        "fn get(&mut self, description: &str) -> Result<Option<Zeroizing<Vec<u8>>>, CacheError> {",
    )
    expected = "let buffer = Zeroizing::new(key.read_to_vec().map_err(|_| CacheError::Unavailable)?);"
    if get_body is None or expected not in get_body:
        validator.fail("LINUX_KEYUTILS_ZEROIZING_READ", cache_path, "keyutils result must be wrapped immediately in Zeroizing")
    if re.search(r"let\s+(?:mut\s+)?buffer\s*=\s*key\.read_to_vec\(", get_body or ""):
        validator.fail("LINUX_KEYUTILS_ZEROIZING_READ", cache_path, "keyutils payload must enter Zeroizing immediately")
