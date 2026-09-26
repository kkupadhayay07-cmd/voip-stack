//! Stable-runnable fuzz smoke corpus for the SDP parser.
//!
//! Handcrafted nasty inputs fed through the same public entry point as
//! `fuzz/fuzz_targets/parse_sdp.rs` (`sdp::parse(&str)`). Property: **the
//! parser returns `Result` for any input and never panics.** The fuzz target
//! takes `&[u8]` and rejects invalid UTF-8 up front (std `str` invariant);
//! here every entry is valid UTF-8 by construction but otherwise hostile.
//!
//! Run on stable CI via `cargo test -p sdp --test fuzz_smoke`.

use sdp::parse;

fn assert_no_panic(corpus: &[&str]) {
    for input in corpus {
        // Deliberately not unwrapped: Err is a perfectly fine outcome.
        let _ = parse(input);
    }
}

#[test]
fn sdp_parser_survives_malformed_corpus() {
    let many_formats: String = {
        let mut s = String::from("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\n");
        s.push_str("c=IN IP4 127.0.0.1\r\nt=0 0\r\n");
        s.push_str("m=audio 5004 RTP/AVP");
        for pt in 0..10_000 {
            s.push_str(&format!(" {pt}"));
        }
        s.push_str("\r\n");
        s
    };
    let huge_line: String = {
        let mut s = String::from("v=0\r\ns=");
        s.extend(std::iter::repeat('x').take(200_000));
        s.push_str("\r\n");
        s
    };
    let many_media: String = {
        let mut s = String::from("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n");
        for i in 0..2_000 {
            s.push_str(&format!("m=audio {i} RTP/AVP 0\r\n"));
        }
        s
    };

    let corpus: Vec<String> = vec![
        String::new(),
        "v=0\r\n".into(), // missing o=/s=
        "v=1\r\no=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\n".into(), // bad version
        "v=0\r\no=- 0 0 IN IP4 1.2.3".into(),              // truncated
        "hello\r\nv=0\r\n".into(),                          // line without '='
        "x=weird\r\n".into(),                               // unknown type
        "m=audio 99999999999999 RTP/AVP 0\r\n".into(),      // port overflow
        "m=audio -1 RTP/AVP 0\r\n".into(),                  // negative port
        "m=audio 5004 RTP/AVP 999\r\n".into(),              // payload type > 127
        "m=audio 5004 RTP/AVP\r\n".into(),                  // no formats
        "m= 5004 RTP/AVP 0\r\n".into(),                     // missing media kind
        "a=rtpmap:0\r\n".into(),                            // rtpmap without value
        "a=rtpmap:0 PCMU/8000/1/2/3\r\n".into(),            // garbage rtpmap
        "a=rtpmap:999 PCMU/8000\r\n".into(),                // rtpmap pt overflow
        "a=no-colon-attribute-value\r\n".into(),            // flag attribute (may be ok)
        "c=notanaddress\r\n".into(),                        // garbage connection
        "c=IN IP4 999.999.999.999\r\n".into(),              // absurd host
        "t=not a time\r\n".into(),                          // garbage timing
        "t=0\r\n".into(),                                   // truncated timing
        "b=AS:-99999999999999999999\r\n".into(),            // bandwidth overflow
        "z=0 0 0 0 0 0 0 0\r\n".into(),                     // timezone garbage
        "v=0\r\ns=\u{1}\u{2}\u{7f}\r\n".into(),             // control chars / DEL
        "v=0\r\ns=\u{1F600}\u{2603}\r\n".into(),            // emoji (valid UTF-8)
        "v=0\r\no=-\0 0 0 IN IP4 1.2.3.4\r\ns=-\r\n".into(), // NUL byte
        "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\no=- 2 2 IN IP4 1.2.3.4\r\ns=-\r\n".into(), // dup o=
        many_formats,
        huge_line,
        many_media,
    ];
    let refs: Vec<&str> = corpus.iter().map(|s| s.as_str()).collect();
    assert_no_panic(&refs);
}
