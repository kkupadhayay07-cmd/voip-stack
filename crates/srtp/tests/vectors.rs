//! RFC conformance vectors for the SRTP crate.
//!
//! - RFC 3711 Appendix B.3: AES-CM key derivation (via the KDF unit tests
//!   and through `SrtpSession::new` below)
//! - RFC 7714 §16.1.1 / §16.1.2 / §16.1.4 / §16.2.1: SRTP AEAD_AES_128/256_GCM
//! - RFC 7714 §17.1 / §17.3: SRTCP AEAD_AES_128_GCM (encrypted E=1 and
//!   tagging-only E=0), pinning the `cipher || tag || E-flag|index` wire
//!   order and the §9.3 authenticate-only path for unencrypted packets

use srtp::{Profile, SessionKeySet, SrtpError, SrtpSession};

/// Build a session from raw session keys.  The RFC 7714 §16 vectors specify
/// the session key/salt directly, with no RFC 3711 derivation step.
fn session_from_raw(profile: Profile, key: &[u8], salt: &[u8]) -> SrtpSession {
    let keys = SessionKeySet {
        enc: key.to_vec(),
        auth: if profile.is_aead() {
            vec![]
        } else {
            vec![0u8; 20]
        },
        salt: salt.to_vec(),
    };
    SrtpSession::from_session_keys(profile, keys.clone(), keys).unwrap()
}

/// RFC 7714 §16 sample packet: header `8040f17b 8041f8d3 5501a0b2`, payload
/// "Gallia est omnis divisa in partes tres", salt "Quid pro quo", keys
/// 00..0f (128-bit) and 00..1f (256-bit).
fn rfc7714_sample_packet() -> Vec<u8> {
    let mut p = hex::decode("8040f17b8041f8d35501a0b2").unwrap();
    p.extend_from_slice(b"Gallia est omnis divisa in partes tres");
    p
}

#[test]
fn rfc7714_16_1_1_aes128_gcm_encrypt() {
    let key = (0u8..=15).collect::<Vec<u8>>();
    let salt = hex::decode("517569642070726f2071756f").unwrap(); // "Quid pro quo"
    let mut session = session_from_raw(Profile::AeadAes128Gcm, &key, &salt);

    // The RFC IV corresponds to SSRC 5501a0b2, ROC 0, SEQ f17b.
    session.set_send_roc(0x5501a0b2, 0);

    let mut packet = rfc7714_sample_packet();
    session.protect(&mut packet).unwrap();

    let expected = hex::decode(concat!(
        "8040f17b8041f8d35501a0b2",
        "f24de3a3fb34de6cacba861c9d7e4bca",
        "be633bd50d294e6f42a5f47a51c7d19b",
        "36de3adf8833",
        "899d7f27beb16a9152cf765ee4390cce"
    ))
    .unwrap();
    assert_eq!(packet, expected, "AES-128-GCM SRTP ciphertext+tag mismatch");
}

#[test]
fn rfc7714_16_2_1_aes256_gcm_encrypt() {
    let key = (0u8..=31).collect::<Vec<u8>>();
    let salt = hex::decode("517569642070726f2071756f").unwrap();
    let mut session = session_from_raw(Profile::AeadAes256Gcm, &key, &salt);
    session.set_send_roc(0x5501a0b2, 0);

    let mut packet = rfc7714_sample_packet();
    session.protect(&mut packet).unwrap();

    let expected = hex::decode(concat!(
        "8040f17b8041f8d35501a0b2",
        "32b1de78a822fe12ef9f78fa332e33aa",
        "b18012389a58e2f3b50b2a0276ffae0f",
        "1ba63799b87b",
        "7aa3db36dfffd6b0f9bb7878d7a76c13"
    ))
    .unwrap();
    assert_eq!(packet, expected, "AES-256-GCM SRTP ciphertext+tag mismatch");
}

#[test]
fn rfc7714_16_1_2_decrypt_roundtrip() {
    // 16.1.2 decrypts the same packet; our decrypt path must reproduce the
    // original RTP packet exactly.
    let key = (0u8..=15).collect::<Vec<u8>>();
    let salt = hex::decode("517569642070726f2071756f").unwrap();
    let mut session = session_from_raw(Profile::AeadAes128Gcm, &key, &salt);
    session.set_recv_roc(0x5501a0b2, 0);

    let mut packet = hex::decode(concat!(
        "8040f17b8041f8d35501a0b2",
        "f24de3a3fb34de6cacba861c9d7e4bca",
        "be633bd50d294e6f42a5f47a51c7d19b",
        "36de3adf8833",
        "899d7f27beb16a9152cf765ee4390cce"
    ))
    .unwrap();
    session.unprotect(&mut packet).unwrap();
    assert_eq!(packet, rfc7714_sample_packet());
}

#[test]
fn rfc7714_16_1_4_tamper_fails() {
    let key = (0u8..=15).collect::<Vec<u8>>();
    let salt = hex::decode("517569642070726f2071756f").unwrap();
    let mut session = session_from_raw(Profile::AeadAes128Gcm, &key, &salt);
    session.set_recv_roc(0x5501a0b2, 0);

    let mut packet = hex::decode(concat!(
        "8040f17b8041f8d35501a0b2",
        "f24de3a3fb34de6cacba861c9d7e4bca",
        "be633bd50d294e6f42a5f47a51c7d19b",
        "36de3adf8833",
        "899d7f27beb16a9152cf765ee4390cce"
    ))
    .unwrap();
    let n = packet.len();
    packet[n - 1] ^= 0x01; // flip one tag bit
    assert_eq!(
        session.unprotect(&mut packet),
        Err(srtp::SrtpError::AuthFailed)
    );
}

/// RFC 3711 B.3 master keying material through the public session API:
/// the 14-octet salt is only valid for AES-CM profiles (GCM uses 12).
#[test]
fn rfc3711_kdf_via_session_construction() {
    let mk = hex::decode("E1F97A0D3E018BE0D64FA32C06DE4139").unwrap();
    let ms = hex::decode("0EC675AD498AFEEBB6960B3AABE6").unwrap();
    for profile in [Profile::AesCm128Sha1_80, Profile::AesCm128Sha1_32] {
        let s = SrtpSession::new(profile, &mk, &ms);
        assert!(s.is_ok(), "{profile:?} should accept RFC 3711 master keys");
    }
    // GCM profiles must reject the 14-octet salt.
    assert!(SrtpSession::new(Profile::AeadAes128Gcm, &mk, &ms).is_err());
}

/// RFC 7714 §17.1: SRTCP AEAD_AES_128_GCM encryption vector.  Pins the
/// `header || ciphertext || GCM tag || E-flag|index` wire order and the
/// `header || E-flag|index` AAD (the tag sits before the index word).
#[test]
fn rfc7714_17_1_srtcp_aes128_gcm_decrypt() {
    let key = (0u8..=15).collect::<Vec<u8>>();
    let salt = hex::decode("517569642070726f2071756f").unwrap(); // "Quid pro quo"
    let mut session = session_from_raw(Profile::AeadAes128Gcm, &key, &salt);

    let mut wire = hex::decode(concat!(
        "81c8000d4d617273",
        "63e94885dcdab67ca727d7662f6b7e99",
        "7ff5c0f76c06f32dc676a5f1730d6fda",
        "4ce09b4686303ded0bb9275b",
        "c84aa45896cf4d2fc5abf87245d9eade",
        "800005d4"
    ))
    .unwrap();
    let idx = session.unprotect_rtcp(&mut wire).unwrap();
    assert_eq!(idx, 0x5d4, "SRTCP index from the E-flag word");
    assert_eq!(
        wire,
        hex::decode(concat!(
            "81c8000d4d617273",
            "4e5450314e545032",
            "525450200000042a",
            "0000e9304c756e61",
            "deadbeefdeadbeefdeadbeefdeadbeef",
            "deadbeef"
        ))
        .unwrap(),
        "§17.1: decryption must restore the plaintext RTCP packet"
    );
}

/// RFC 7714 §17.3: SRTCP AEAD_AES_128_GCM tagging-only vector (E=0).  The
/// plaintext is empty, the whole packet (header || body || E-flag|index) is
/// AAD, and the GCM tag sits before the E-flag|index word.
#[test]
fn rfc7714_17_3_srtcp_aes128_gcm_e0_tag_only() {
    let key = (0u8..=15).collect::<Vec<u8>>();
    let salt = hex::decode("517569642070726f2071756f").unwrap();
    let mut session = session_from_raw(Profile::AeadAes128Gcm, &key, &salt);

    let original = hex::decode(concat!(
        "81c8000d4d617273",
        "4e5450314e545032",
        "525450200000042a",
        "0000e9304c756e61",
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "deadbeef"
    ))
    .unwrap();
    let mut wire = original.clone();
    wire.extend_from_slice(&hex::decode("841dd9683dd78ec92ae58790125f62b3").unwrap());
    wire.extend_from_slice(&hex::decode("000005d4").unwrap()); // E=0, index 1492

    let idx = session.unprotect_rtcp(&mut wire).unwrap();
    assert_eq!(idx, 0x5d4);
    assert_eq!(
        wire, original,
        "§17.3: E=0 packet must come back without the tag/index trailer"
    );
}

/// §17.3 with a tampered body byte: E=0 SRTCP is authenticate-only, so any
/// modification must fail tag verification.
#[test]
fn rfc7714_17_3_srtcp_e0_tamper_fails() {
    let key = (0u8..=15).collect::<Vec<u8>>();
    let salt = hex::decode("517569642070726f2071756f").unwrap();
    let mut session = session_from_raw(Profile::AeadAes128Gcm, &key, &salt);

    let mut wire = hex::decode(concat!(
        "81c8000d4d617273",
        "4e5450314e545032",
        "525450200000042a",
        "0000e9304c756e61",
        "deadbeefdeadbeefdeadbeefdeadbeef",
        "deadbeef",
        "841dd9683dd78ec92ae58790125f62b3",
        "000005d4"
    ))
    .unwrap();
    wire[12] ^= 0x01; // flip one bit inside the authenticated body
    assert_eq!(
        session.unprotect_rtcp(&mut wire),
        Err(SrtpError::AuthFailed)
    );
}
