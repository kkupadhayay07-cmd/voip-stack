use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sdp::parse;

const OFFER: &str = "\
v=0\r\n\
o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8 101\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:EsAw\r\n\
a=ice-pwd:P2uYro0UCOQ4zxjKXaWCBui1\r\n\
a=fingerprint:sha-256 D2:FA:0E:C3:22:59:5E:14:95:69:92:3D:13:B4:84:24:2C:C2:A2:C0:3E:FD:34:8E:5E:EA:6F:AF:52:CE:E6:0F\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n\
a=sendrecv\r\n\
a=rtcp-mux\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=fmtp:111 minptime=10;useinbandfec=1\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-16\r\n";

fn bench_sdp_parse(c: &mut Criterion) {
    c.bench_function("sdp_parse_webrtc_offer", |b| {
        b.iter(|| parse(black_box(OFFER)).unwrap())
    });
}

fn bench_sdp_roundtrip(c: &mut Criterion) {
    let sess = parse(OFFER).unwrap();
    c.bench_function("sdp_serialize", |b| b.iter(|| black_box(sess.serialize())));
}

criterion_group!(benches, bench_sdp_parse, bench_sdp_roundtrip);
criterion_main!(benches);
