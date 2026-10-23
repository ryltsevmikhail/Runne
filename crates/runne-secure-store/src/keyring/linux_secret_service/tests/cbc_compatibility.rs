//! Public NIST SP800-38A F.2.1 / RFC3602 section4 raw prefixes;
//! complete PKCS#7 answers independently cross-checked with OpenSSL3.6.5.
//! Catches wrong AES key/mode/IV, padding, payload and wipe/error behavior.
use super::*;

#[test]
fn nist_and_rfc3602_complete_ciphertext_known_answers() {
    let vectors = [
        (
            "nist",
            "2b7e151628aed2a6abf7158809cf4f3c",
            "000102030405060708090a0b0c0d0e0f",
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a78cb82807230e1321d3fae00d18cc2012",
        ),
        (
            "rfc1",
            "06a9214036b8a15b512e03d534120006",
            "3dafba429d9eb430b422da802c9fac41",
            "53696e676c6520626c6f636b206d7367",
            "e353779c1079aeb82708942dbe77181ab97c825e1c785146542d396941bce55d",
        ),
        (
            "rfc2",
            "c286696d887c9aa0611bbb3e2025a45a",
            "562e17996d093d28ddb3ba695a2e6f58",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1bcfd81022202366bde6dd260a15841a1",
        ),
        (
            "rfc3",
            "6c3ea0477630ce21a2ce334aa746c2cd",
            "c782dc4c098c66cbd9cd27d825682c81",
            "5468697320697320612034382d62797465206d657373616765202865786163746c7920332041455320626c6f636b7329",
            "d0a02b3836451753d493665d33f0e8862dea54cdb293abc7506939276772f8d5021c19216bad525c8579695d83ba2684d248b3e0f2388c137102846eb06272ff",
        ),
        (
            "rfc4",
            "56e47a38c5598974bc46903dba290349",
            "8ce82eefbea0da3c44699ed7db51b7d9",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
            "c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da5578b8d04731041aa2d9787ca4a4fa3eef",
        ),
    ];
    for (name, key, iv, plaintext, expected) in vectors {
        let key: [u8; 16] = hex::decode(key).unwrap().try_into().unwrap();
        let iv: [u8; 16] = hex::decode(iv).unwrap().try_into().unwrap();
        let plaintext = hex::decode(plaintext).unwrap();
        let expected = hex::decode(expected).unwrap();
        let cipher = encrypt_with_iv(&plaintext, &key, &iv);
        assert_eq!(cipher, expected, "{name}");
        assert_eq!(cipher.len(), (plaintext.len() / 16 + 1) * 16);
        assert_eq!(&*decrypt_with_iv(&expected, &key, &iv).unwrap(), &plaintext);
        println!("CBC {name} ciphertext={}", hex::encode(cipher));
    }
}

#[test]
fn pkcs7_boundary_complete_ciphertext_known_answers() {
    let vectors = [
        (
            "length0",
            "31313131313131313131313131313131",
            "72727272727272727272727272727272",
            "",
            "169e1ed0fa3340c6354964dfe23af33b",
        ),
        (
            "length1",
            "31313131313131313131313131313131",
            "72727272727272727272727272727272",
            "00",
            "085ab312c3650b13120336c4b45a05eb",
        ),
        (
            "length15",
            "31313131313131313131313131313131",
            "72727272727272727272727272727272",
            "00112233445566778899aabbccddee",
            "9183a07948dfd6261d16cbd7c706e84f",
        ),
        (
            "length16",
            "31313131313131313131313131313131",
            "72727272727272727272727272727272",
            "00112233445566778899aabbccddeeff",
            "edafae6d9d01624446fd023d565f70244d2c25fc30932cc97accb03ca2c65c97",
        ),
        (
            "length17",
            "31313131313131313131313131313131",
            "72727272727272727272727272727272",
            "00112233445566778899aabbccddeeff10",
            "edafae6d9d01624446fd023d565f70240a4e8eff844d1377326ceee956328238",
        ),
        (
            "length31",
            "31313131313131313131313131313131",
            "72727272727272727272727272727272",
            "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe",
            "edafae6d9d01624446fd023d565f70243a7f87766e6d907848260e4c4ff2b0f1",
        ),
        (
            "length32",
            "31313131313131313131313131313131",
            "72727272727272727272727272727272",
            "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
            "edafae6d9d01624446fd023d565f7024fc9b63bf8db2bfe47a25ca4e6c42bbdbb601c1c08b544071f83a25e825027e3a",
        ),
    ];
    for (name, key, iv, plaintext, expected) in vectors {
        let key: [u8; 16] = hex::decode(key).unwrap().try_into().unwrap();
        let iv: [u8; 16] = hex::decode(iv).unwrap().try_into().unwrap();
        let plaintext = hex::decode(plaintext).unwrap();
        let expected = hex::decode(expected).unwrap();
        let cipher = encrypt_with_iv(&plaintext, &key, &iv);
        assert_eq!(cipher, expected, "{name}");
        assert_eq!(cipher.len(), (plaintext.len() / 16 + 1) * 16);
        assert_eq!(&*decrypt_with_iv(&expected, &key, &iv).unwrap(), &plaintext);
        println!("CBC {name} ciphertext={}", hex::encode(cipher));
    }
}

#[test]
fn nist_raw_decrypt_all_four_blocks() {
    use aes::cipher::block_padding::NoPadding;
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let mut cipher = hex::decode(concat!(
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b27",
        "3bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
    ))
    .unwrap();
    let expected = hex::decode(concat!(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    ))
    .unwrap();
    let plain = Aes128CbcDec::new_from_slices(&key, &iv)
        .unwrap()
        .decrypt_padded::<NoPadding>(&mut cipher)
        .unwrap();
    assert_eq!(plain, expected);
}

#[test]
fn wire_fields_random_iv_and_binary_payload_are_preserved() {
    let session = DhSession {
        session_path: "/org/freedesktop/secrets/session/fixture".to_owned(),
        shared_key: Zeroizing::new([0x31; 16]),
    };
    let payload = [0, 255, 128, 1, 0];
    let mime = "application/octet-stream; fixture=cbc";
    for _ in 0..4 {
        let wire = session.encrypt(&payload, mime);
        assert_eq!(wire.session_path, session.session_path);
        assert_eq!(wire.mime, mime);
        let iv: [u8; 16] = wire.iv.clone().try_into().unwrap();
        assert_eq!(wire.data, encrypt_with_iv(&payload, &[0x31; 16], &iv));
        assert_eq!(&*session.decrypt(&wire).unwrap(), &payload);
        println!(
            "CBC wire session={} mime={} payload={}",
            wire.session_path,
            wire.mime,
            hex::encode(payload)
        );
    }
    let mut wire = session.encrypt(&payload, mime);
    wire.session_path = "/foreign".to_owned();
    assert!(matches!(session.decrypt(&wire), Err(SsBusError::Transport)));
}

#[test]
fn malformed_wire_lengths_are_transport_errors() {
    let key = [0x31; 16];
    let iv = [0x72; 16];
    let valid = encrypt_with_iv(b"fixture", &key, &iv);
    for n in [0, 15, 17] {
        assert!(matches!(
            decrypt_with_iv(&valid, &key, &vec![0; n]),
            Err(SsBusError::Transport)
        ));
    }
    for n in [0, 1, 15, 17, 31, MAX_CIPHERTEXT_BYTES + 16] {
        assert!(matches!(
            decrypt_with_iv(&vec![0; n], &key, &iv),
            Err(SsBusError::Transport)
        ));
    }
    let plain = vec![0x80; MAX_ENCODED_PROVIDER_CREDENTIAL_BYTES];
    let cipher = encrypt_with_iv(&plain, &key, &iv);
    assert_eq!(cipher.len(), MAX_CIPHERTEXT_BYTES);
    assert_eq!(&*decrypt_with_iv(&cipher, &key, &iv).unwrap(), &plain);
}

#[test]
fn deterministic_invalid_padding_and_prevalidation_clear_guarded_scratch() {
    let key = [0x44; 16];
    let iv = [0x55; 16];
    let mut inconsistent = [2; 16];
    inconsistent[14] = 3;
    let mut invalid_full = [16; 16];
    invalid_full[0] = 15;
    for bad in [[0; 16], [17; 16], inconsistent, invalid_full] {
        // First block of an aligned encryption is raw CBC of the chosen block.
        let ciphertext = encrypt_with_iv(&bad, &key, &iv)[..16].to_vec();
        assert!(matches!(
            decrypt_with_iv(&ciphertext, &key, &iv),
            Err(SsBusError::Transport)
        ));
        let mut scratch = Zeroizing::new(ciphertext);
        assert!(matches!(
            decrypt_padded_in_place(&mut scratch, &key, &iv),
            Err(SsBusError::Transport)
        ));
        assert!(scratch.is_empty()); // Clearing, not a freed-memory inspection.
    }
    for (buffer, bad_iv) in [
        (vec![], vec![0; 16]),
        (vec![1; 15], vec![0; 16]),
        (vec![1; 16], vec![0; 15]),
    ] {
        let mut scratch = Zeroizing::new(buffer);
        assert!(matches!(
            decrypt_padded_in_place(&mut scratch, &key, &bad_iv),
            Err(SsBusError::Transport)
        ));
        assert!(scratch.is_empty());
    }
}

#[test]
fn success_padding_tail_is_zero_before_truncation_and_owned_slice_wipes() {
    for n in [0, 1, 15, 16, 17, 31, 32] {
        let plaintext = vec![0xa5; n];
        let mut scratch = Zeroizing::new(encrypt_with_iv(&plaintext, &[0x31; 16], &[0x72; 16]));
        let padded_len = scratch.len();
        let len = decrypt_padded_in_place(&mut scratch, &[0x31; 16], &[0x72; 16]).unwrap();
        assert_eq!(len, n);
        assert_eq!(&scratch[..len], &plaintext);
        assert_eq!(scratch.len(), padded_len);
        assert!(!scratch[len..].is_empty());
        assert!(scratch[len..].iter().all(|b| *b == 0));
    }
    let mut owned = [0xa5; 64];
    owned[8..56].zeroize();
    assert_eq!(&owned[8..56], &[0; 48]);
    assert_eq!(&owned[..8], &[0xa5; 8]);
    owned.zeroize();
    assert_eq!(owned, [0; 64]);
}
