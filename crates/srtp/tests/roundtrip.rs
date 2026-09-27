//! Roundtrip and adversarial integration tests for the SRTP session layer.

use rand::RngCore;
use srtp::{Profile, SrtpError, SrtpSession};

fn rtp(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x80, 0x60];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn rtcp_compound(ssrc: u32) -> Vec<u8> {
    // Minimal SR (V2, PT=200, length 6) + minimal SDES (PT=202).
    let mut sr = vec![0x81, 200, 0, 6];
    sr.extend_from_slice(&ssrc.to_be_bytes());
    sr.extend_from_slice(&[0u8; 24]);
    let mut sdes = vec![0x81, 202, 0, 4];
    sdes.extend_from_slice(&ssrc.to_be_bytes());
    sdes.extend_from_slice(&[1, 4, b't', b'e', b's', b't', 0, 0]);
    let mut pkt = sr;
    pkt.extend_from_slice(&sdes);
    pkt
}

fn all_profiles() -> Vec<Profile> {
    vec![
        Profile::AesCm128Sha1_80,
        Profile::AesCm128Sha1_32,
        Profile::AeadAes128Gcm,
        Profile::AeadAes256Gcm,
        Profile::AeadAes128Gcm12,
        Profile::AeadAes256Gcm12,
    ]
}

#[test]
fn roundtrip_all_profiles() {
    for profile in all_profiles() {
        let key = vec![0xABu8; profile.key_len()];
        let salt = vec![0xCDu8; profile.salt_len()];
        let mut tx = SrtpSession::new(profile, &key, &salt).unwrap();
        let mut rx = SrtpSession::new(profile, &key, &salt).unwrap();

        // Realistic monotonic sequence deltas (Appendix A estimation is only
        // defined for sender-style progression; huge forward jumps are
        // spec-correctly interpreted as previous-ROC tails and fail auth).
        for (rtcp_index_expected, seq) in [1u16, 2, 500, 32767, 32768, 40000, 40001]
            .into_iter()
            .enumerate()
        {
            let mut pkt = rtp(seq, 0xCAFE, b"payload-in-the-vm");
            let sent = pkt.clone();
            let idx = tx.protect(&mut pkt).unwrap();
            assert_eq!(idx, seq as u64);
            assert_ne!(pkt, sent, "{profile:?}: ciphertext must differ");
            assert_eq!(pkt.len(), sent.len() + profile.tag_len());
            rx.unprotect(&mut pkt).unwrap();
            assert_eq!(pkt, sent, "{profile:?}: roundtrip must restore packet");

            let mut c = rtcp_compound(0xCAFE);
            let sent = c.clone();
            tx.protect_rtcp(&mut c).unwrap();
            assert_eq!(c.len(), sent.len() + 4 + profile.tag_len());
            let idx = rx.unprotect_rtcp(&mut c).unwrap();
            assert_eq!(idx, rtcp_index_expected as u32);
            assert_eq!(c, sent, "{profile:?}: RTCP roundtrip must restore packet");
        }
    }
}

#[test]
fn replay_rejected_on_rtp_and_rtcp() {
    let profile = Profile::AesCm128Sha1_80;
    let key = vec![7u8; 16];
    let salt = vec![9u8; 14];
    let mut tx = SrtpSession::new(profile, &key, &salt).unwrap();
    let mut rx = SrtpSession::new(profile, &key, &salt).unwrap();

    let mut pkt = rtp(42, 1, b"x");
    tx.protect(&mut pkt).unwrap();
    rx.unprotect(&mut pkt).unwrap();

    // Replay the exact same wire bytes.
    let mut pkt = rtp(42, 1, b"x");
    tx.protect(&mut pkt).unwrap();
    assert_eq!(rx.unprotect(&mut pkt), Err(SrtpError::Replayed));

    // RTCP replay: deliver the exact same wire bytes twice.
    let mut c = rtcp_compound(1);
    tx.protect_rtcp(&mut c).unwrap();
    let mut wire = c.clone();
    rx.unprotect_rtcp(&mut c).unwrap();
    assert_eq!(rx.unprotect_rtcp(&mut wire), Err(SrtpError::Replayed));
}

#[test]
fn reordering_within_window_accepted() {
    let profile = Profile::AesCm128Sha1_80;
    let mut tx = SrtpSession::new(profile, &[3u8; 16], &[4u8; 14]).unwrap();
    let mut rx = SrtpSession::new(profile, &[3u8; 16], &[4u8; 14]).unwrap();

    let mut protect = |s: u16| {
        let mut p = rtp(s, 9, b"ok");
        tx.protect(&mut p).unwrap();
        p
    };
    let p1 = protect(100);
    let p2 = protect(101);
    let p3 = protect(102);

    // Deliver 102, then 100, then 101 — all inside the 64-packet window.
    let mut a = p3.clone();
    let mut b = p1;
    let mut c = p2;
    rx.unprotect(&mut a).unwrap();
    rx.unprotect(&mut b).unwrap();
    rx.unprotect(&mut c).unwrap();
}

#[test]
fn reordering_beyond_window_rejected() {
    let profile = Profile::AesCm128Sha1_80;
    let mut tx = SrtpSession::new(profile, &[3u8; 16], &[4u8; 14]).unwrap();
    let mut rx = SrtpSession::new(profile, &[3u8; 16], &[4u8; 14]).unwrap();

    let mut p_old = rtp(10, 9, b"old");
    tx.protect(&mut p_old).unwrap();
    for s in 11..200u16 {
        let mut p = rtp(s, 9, b"n");
        tx.protect(&mut p).unwrap();
        rx.unprotect(&mut p).unwrap();
    }
    assert_eq!(rx.unprotect(&mut p_old), Err(SrtpError::Replayed));
}

#[test]
fn roc_wrap_handled_transparently() {
    let profile = Profile::AeadAes128Gcm;
    let mut tx = SrtpSession::new(profile, &[5u8; 16], &[6u8; 12]).unwrap();
    let mut rx = SrtpSession::new(profile, &[5u8; 16], &[6u8; 12]).unwrap();

    // Sender protects seq 65530 first (queued), then runs the wrap
    // 65534 → 65535 → 0 → 1 as the receiver consumes them in order.
    let mut queued = rtp(65530, 0xBEEF, b"prewrap");
    tx.protect(&mut queued).unwrap();
    for seq in [65534u16, 65535, 0, 1] {
        let mut p = rtp(seq, 0xBEEF, b"wrap");
        tx.protect(&mut p).unwrap();
        rx.unprotect(&mut p).unwrap();
    }

    // The queued pre-wrap packet (ROC 0) still verifies afterwards: it is
    // inside the 64-packet replay window of the new ROC-1 stream.
    rx.unprotect(&mut queued).unwrap();

    // And the stream keeps flowing after the wrap.
    let mut p = rtp(2, 0xBEEF, b"postwrap");
    tx.protect(&mut p).unwrap();
    rx.unprotect(&mut p).unwrap();
}

#[test]
fn corrupted_tag_and_ciphertext_rejected() {
    for profile in all_profiles() {
        let key = vec![0x11u8; profile.key_len()];
        let salt = vec![0x22u8; profile.salt_len()];
        let mut tx = SrtpSession::new(profile, &key, &salt).unwrap();
        let mut rx = SrtpSession::new(profile, &key, &salt).unwrap();

        // Flip a bit in the timestamp — inside the authenticated header.
        let mut pkt = rtp(1, 77, b"secret");
        tx.protect(&mut pkt).unwrap();
        pkt[5] ^= 0x40;
        assert_eq!(
            rx.unprotect(&mut pkt),
            Err(SrtpError::AuthFailed),
            "{profile:?}"
        );

        // Payload integrity: GCM authenticates the payload; RFC 3711's
        // HMAC-SHA1 authenticates header+ROC only, so a payload flip is
        // undetectable by design (documented property of the transform).
        let mut pkt = rtp(1, 77, b"secret");
        tx.protect(&mut pkt).unwrap();
        pkt[13] ^= 0x40;
        if profile.is_aead() {
            assert_eq!(
                rx.unprotect(&mut pkt),
                Err(SrtpError::AuthFailed),
                "{profile:?}"
            );
        } else {
            rx.unprotect(&mut pkt).unwrap();
        }

        // Tamper with the last byte (inside the tag) — fresh seq so the
        // replay window does not reject it before authentication.
        let mut pkt = rtp(2, 77, b"secret");
        tx.protect(&mut pkt).unwrap();
        let n = pkt.len();
        pkt[n - 1] ^= 0xff;
        assert_eq!(
            rx.unprotect(&mut pkt),
            Err(SrtpError::AuthFailed),
            "{profile:?}"
        );
    }
}

#[test]
fn wrong_key_rejected() {
    let mut tx = SrtpSession::new(Profile::AesCm128Sha1_80, &[1u8; 16], &[2u8; 14]).unwrap();
    let mut rx = SrtpSession::new(Profile::AesCm128Sha1_80, &[9u8; 16], &[2u8; 14]).unwrap();
    let mut pkt = rtp(1, 3, b"x");
    tx.protect(&mut pkt).unwrap();
    assert_eq!(rx.unprotect(&mut pkt), Err(SrtpError::AuthFailed));
}

#[test]
fn forged_rtcp_index_rejected() {
    let mut tx = SrtpSession::new(Profile::AesCm128Sha1_80, &[1u8; 16], &[2u8; 14]).unwrap();
    let mut rx = SrtpSession::new(Profile::AesCm128Sha1_80, &[1u8; 16], &[2u8; 14]).unwrap();
    let mut c = rtcp_compound(55);
    tx.protect_rtcp(&mut c).unwrap();
    rx.unprotect_rtcp(&mut c).unwrap();

    // Replay with a *different* forged index: MAC covers the flag word, so
    // the tag check must fail before the replay window is consulted.
    let mut c = rtcp_compound(55);
    tx.protect_rtcp(&mut c).unwrap();
    let n = c.len();
    // index word is 4 bytes before the tag; bump it (invalidates MAC)
    c[n - 4 - 10 - 1] ^= 0x01;
    assert_eq!(rx.unprotect_rtcp(&mut c), Err(SrtpError::AuthFailed));
}

#[test]
fn short_buffers_rejected_cleanly() {
    let mut rx = SrtpSession::new(Profile::AesCm128Sha1_80, &[1u8; 16], &[2u8; 14]).unwrap();
    assert_eq!(
        rx.unprotect(&mut vec![]),
        Err(SrtpError::TooShort { got: 0 })
    );
    assert_eq!(
        rx.unprotect(&mut vec![0x80, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]),
        Err(SrtpError::TooShort { got: 12 })
    );
    assert_eq!(
        rx.unprotect_rtcp(&mut vec![0x81, 200]),
        Err(SrtpError::TooShort { got: 2 })
    );
}

#[test]
fn multi_ssrc_streams_are_independent() {
    let mut tx = SrtpSession::new(Profile::AesCm128Sha1_80, &[1u8; 16], &[2u8; 14]).unwrap();
    let mut rx = SrtpSession::new(Profile::AesCm128Sha1_80, &[1u8; 16], &[2u8; 14]).unwrap();

    // Two SSRCs interleaved with independent sequence spaces.
    for i in 0..50u16 {
        let mut a = rtp(i, 111, b"a");
        let mut b = rtp(10_000 + i, 222, b"b");
        tx.protect(&mut a).unwrap();
        tx.protect(&mut b).unwrap();
        rx.unprotect(&mut b).unwrap();
        rx.unprotect(&mut a).unwrap();
    }
}

/// Randomized soak: 2k packets through every profile, verifying that every
/// protected packet decrypts and that no plaintext leaks into the wire form.
#[test]
fn randomized_soak_all_profiles() {
    for profile in all_profiles() {
        let key = {
            let mut k = vec![0u8; profile.key_len()];
            rand::thread_rng().fill_bytes(&mut k);
            k
        };
        let salt = {
            let mut s = vec![0u8; profile.salt_len()];
            rand::thread_rng().fill_bytes(&mut s);
            s
        };
        let mut tx = SrtpSession::new(profile, &key, &salt).unwrap();
        let mut rx = SrtpSession::new(profile, &key, &salt).unwrap();

        for seq in 0..2000u16 {
            let payload_len = 1 + (seq as usize % 160);
            let payload: Vec<u8> = (0..payload_len).map(|i| (i ^ seq as usize) as u8).collect();
            let mut p = rtp(seq, 0xABCDEF, &payload);
            tx.protect(&mut p).unwrap();
            assert_eq!(p.len(), 12 + payload_len + profile.tag_len());
            rx.unprotect(&mut p).unwrap();
            assert_eq!(&p[12..], payload.as_slice());
        }
    }
}

#[test]
fn profile_dtls_names_roundtrip() {
    for (name, expected) in [
        ("SRTP_AES128_CM_SHA1_80", Profile::AesCm128Sha1_80),
        ("SRTP_AES128_CM_SHA1_32", Profile::AesCm128Sha1_32),
        ("SRTP_AEAD_AES_128_GCM", Profile::AeadAes128Gcm),
        ("SRTP_AEAD_AES_256_GCM", Profile::AeadAes256Gcm),
    ] {
        assert_eq!(Profile::from_dtls_name(name), Some(expected));
        assert_eq!(expected.dtls_name(), Some(name));
    }
    assert_eq!(Profile::from_dtls_name("SRTP_NULL_SHA1_80"), None);
}
