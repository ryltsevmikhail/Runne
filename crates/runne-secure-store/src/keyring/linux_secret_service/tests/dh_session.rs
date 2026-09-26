use super::*;
use crate::provider_credential::{
    ProviderCredentialAccessPolicy, ProviderCredentialMaterial, ProviderCredentialSourceRevision,
    StoredProviderCredential,
};

#[test]
fn known_answer_dh_hkdf_derivation() {
    let private: [u8; 128] =
        core::array::from_fn(|i| u8::try_from(i).expect("index below 128 fits u8"));
    let server_public = hex::decode(
        "7b1d7d3188d79522e49e1ef8a54a32403fa559965ff46561a8d12fc1f79273e70b2c\
         6ea601992ec15910b87dffa610904bdbc2bdd35b13c95a0d7cb40a0d62720f4a9042\
         59982b507d9981f4eedb7371db1336d26e29d58e2d2da00d7928a64cadc4eb683c0\
         4df21ac4f5f71174805326a640a789679de2fc1b3ed28d2c9ba71",
    )
    .unwrap();
    let key = derive_shared_key(&private, &server_public).unwrap();
    assert_eq!(hex::encode(key), "17ea7a2ea428d753538424667065cea2");
}

#[test]
fn client_public_key_reference() {
    let private: [u8; 128] =
        core::array::from_fn(|i| u8::try_from(i).expect("index below 128 fits u8"));
    let modulus = BigUint::from_bytes_be(DH_PRIME);
    let generator = BigUint::from_u64(2).unwrap();
    let public = pow_mod(&generator, &private, &modulus);
    assert_eq!(
        hex::encode(public.to_bytes_be()),
        "a0c1f547ad5dff7b427d7c09796298448f5ef3b2c5000a3222651ecb2f53d2002461\
         9ed31e2d7577628962de190272633d927b9c06a554df61c68bf73c66c181ba1353d7\
         ea6bd55f9fade8394a30477b2e4033e74ec192a33d3b5801caa50430fb874a8bb1c6\
         f2fd121a446c364207a0d6cb18e4dc0c3729879976f261c8396c"
    );
}

#[test]
fn aes_cbc_nist_exact_block_known_answer() {
    let key: [u8; 16] = hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
        .unwrap()
        .try_into()
        .unwrap();
    let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
        .unwrap()
        .try_into()
        .unwrap();
    let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let ciphertext = encrypt_with_iv(&plaintext, &key, &iv);
    assert_eq!(
        hex::encode(&ciphertext[..16]),
        "7649abac8119b246cee98e9b12e9197d"
    );
    assert_eq!(ciphertext.len(), 32, "full block needs a PKCS#7 block");
    assert_eq!(
        &*decrypt_with_iv(&ciphertext, &key, &iv).unwrap(),
        &plaintext
    );
}

#[test]
fn empty_plaintext_roundtrips_with_one_padding_block() {
    let key = [0x31; 16];
    let iv = [0x72; 16];
    let ciphertext = encrypt_with_iv(&[], &key, &iv);
    assert_eq!(ciphertext.len(), AES_BLOCK_BYTES);
    assert!(decrypt_with_iv(&ciphertext, &key, &iv).unwrap().is_empty());
    assert!(decrypt_with_iv(&[], &key, &iv).is_err());
}

#[test]
fn maximum_stored_oauth_record_roundtrips_and_oversized_ciphertext_is_rejected() {
    let executable = std::env::current_exe().unwrap();
    let access = ProviderCredentialAccessPolicy::new(&executable, &executable).unwrap();
    let material = ProviderCredentialMaterial::new_native_oauth(vec![b'o'; 32 * 1024]).unwrap();
    let revision = ProviderCredentialSourceRevision::new([0x21; 16]).unwrap();
    let encoded =
        StoredProviderCredential::encode_with_revision(&material, &access, [0x71; 32], revision)
            .unwrap();
    assert_eq!(encoded.len(), MAX_ENCODED_PROVIDER_CREDENTIAL_BYTES);

    let key = [0x42; 16];
    let iv = [0x35; AES_BLOCK_BYTES];
    let ciphertext = encrypt_with_iv(&encoded, &key, &iv);
    assert_eq!(ciphertext.len(), MAX_CIPHERTEXT_BYTES);
    assert_eq!(
        &*decrypt_with_iv(&ciphertext, &key, &iv).unwrap(),
        &*encoded
    );

    let oversized = vec![0; MAX_CIPHERTEXT_BYTES + AES_BLOCK_BYTES];
    assert!(decrypt_with_iv(&oversized, &key, &iv).is_err());
}

#[test]
fn malformed_padding_zeroizes_the_decrypted_scratch_buffer() {
    let key = [0x44; 16];
    let iv = [0x55; 16];
    let ciphertext = encrypt_with_iv(b"123456789012345", &key, &iv);
    let mut wrong_iv = iv;
    wrong_iv[AES_BLOCK_BYTES - 1] ^= 1;
    let mut scratch = Zeroizing::new(ciphertext);
    assert!(matches!(
        decrypt_padded_in_place(&mut scratch, &key, &wrong_iv),
        Err(SsBusError::Transport)
    ));
    assert!(
        scratch.is_empty(),
        "failed decrypt clears the scratch buffer"
    );
}

#[test]
fn negotiate_roundtrip_encrypt_decrypt() {
    let server_private: [u8; 128] =
        core::array::from_fn(|i: usize| u8::try_from((i * 7 + 3) & 0xff).unwrap());
    let modulus = BigUint::from_bytes_be(DH_PRIME);
    let generator = BigUint::from_u64(2).unwrap();
    let server_public = pow_mod(&generator, &server_private, &modulus).to_bytes_be();
    let session = DhSession::negotiate(|_algorithm, _public| {
        Ok((
            server_public,
            "/org/freedesktop/secrets/session/f1".to_owned(),
        ))
    })
    .unwrap();
    let wire = session.encrypt(b"runne secret", "text/plain");
    assert_eq!(&*session.decrypt(&wire).unwrap(), b"runne secret");
    let mut foreign = session.encrypt(b"x", "text/plain");
    foreign.session_path = "/other".to_owned();
    assert!(session.decrypt(&foreign).is_err());
}
