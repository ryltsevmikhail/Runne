//! Published vectors against first-party HMAC and the workspace SHA implementation.
//! No HKDF crate: RFC expansion below composes the actual production hmac helper.
use runne_inference_protocol::hmac;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn kat(name: &str, got: &[u8], expected: &str) {
    assert_eq!(hex(got), expected, "{name}");
    println!("CRYPTO {name}={}", hex(got));
}

#[test]
fn sha256_published_known_answers() {
    for (name, input, expected) in [
        (
            "sha-empty",
            Vec::new(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "sha-abc",
            b"abc".to_vec(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "sha-multiblock",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            "sha-million-a",
            vec![b'a'; 1_000_000],
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        ),
    ] {
        kat(name, &Sha256::digest(&input), expected);
        for size in [1, 55, 56, 63, 64, 65] {
            let mut digest = Sha256::new();
            for part in input.chunks(size) {
                digest.update(part);
            }
            assert_eq!(hex(&digest.finalize()), expected);
        }
    }
}

#[test]
fn hmac_sha256_rfc4231_all_cases() {
    let cases = [
        (vec![0x0b;20], b"Hi There".to_vec(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (vec![0xaa;20], vec![0xdd;50], "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        ((1..=25).collect(), vec![0xcd;50], "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        (vec![0x0c;20], b"Test With Truncation".to_vec(), "a3b6167473100ee06e0c796c2955552b"),
        (vec![0xaa;131], b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (vec![0xaa;131], b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(), "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    ];
    for (i, (key, message, expected)) in cases.iter().enumerate() {
        let tag = hmac(key, &[message]);
        kat(
            &format!("rfc4231-{}", i + 1),
            &tag[..expected.len() / 2],
            expected,
        );
        for split in [0, 1, 55, 56, 63, 64, 65, message.len()] {
            let n = split.min(message.len());
            assert_eq!(hmac(key, &[&message[..n], &[], &message[n..]]), tag);
        }
        assert_ne!(hmac(b"wrong key", &[message]), tag);
    }
}

#[test]
fn hmac_key_and_message_boundaries() {
    // Independent RFC2104 ipad/opad construction over SHA, not a second HMAC crate.
    for keylen in [0, 1, 63, 64, 65, 131] {
        let key = vec![0xa5; keylen];
        for size in [0, 1, 55, 56, 63, 64, 65, 129] {
            let message = vec![0x5a; size];
            let normalized = if keylen > 64 {
                Sha256::digest(&key).to_vec()
            } else {
                key.clone()
            };
            let mut ipad = [0x36; 64];
            let mut opad = [0x5c; 64];
            for (i, b) in normalized.iter().enumerate() {
                ipad[i] ^= b;
                opad[i] ^= b;
            }
            let inner = Sha256::new()
                .chain_update(ipad)
                .chain_update(&message)
                .finalize();
            let expected = Sha256::new()
                .chain_update(opad)
                .chain_update(inner)
                .finalize();
            let got = hmac(&key, &[&message]);
            assert_eq!(got.as_slice(), expected.as_slice());
            println!("CRYPTO boundary-{keylen}-{size}={}", hex(&got));
        }
    }
}

fn expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    // Test-only RFC5869 multiblock composition over the actual first-party helper.
    // Production exposes only fixed32-byte expansion, so no new public bounds API.
    assert!(len <= 255 * 32);
    let mut result = Vec::new();
    let mut previous = Vec::new();
    for counter in 1..=len.div_ceil(32) {
        previous = hmac(prk, &[&previous, info, &[counter as u8]]).to_vec();
        result.extend_from_slice(&previous);
    }
    result.truncate(len);
    result
}

#[test]
fn hkdf_sha256_rfc5869_full_prk_and_multiblock_okm() {
    let cases = [
        (
            vec![0x0b; 22],
            (0..=12).collect::<Vec<u8>>(),
            (0xf0..=0xf9).collect::<Vec<u8>>(),
            42,
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            (0..=0x4f).collect(),
            (0x60..=0xaf).collect(),
            (0xb0..=0xff).collect(),
            82,
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
        (
            vec![0x0b; 22],
            Vec::new(),
            Vec::new(),
            42,
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
    ];
    for (i, (ikm, salt, info, len, expected_prk, expected_okm)) in cases.iter().enumerate() {
        let prk = hmac(salt, &[ikm]);
        kat(&format!("rfc5869-prk-{}", i + 1), &prk, expected_prk);
        kat(
            &format!("rfc5869-okm-{}", i + 1),
            &expand(&prk, info, *len),
            expected_okm,
        );
        assert_eq!(
            expand(&unhex(expected_prk), info, 32),
            unhex(&expected_okm[..64])
        );
    }
}
