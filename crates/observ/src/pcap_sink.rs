//! Manual pcap writing/reading (classic libpcap format, LINKTYPE_ETHERNET).
//! Each UDP datagram becomes a full Ethernet + IPv4 + UDP frame so
//! Wireshark decodes SIP and RTP natively — no custom dissectors, no
//! libpcap dependency. IP checksum is written as 0 and the DF bit is set
//! (both accepted by Wireshark and standard for synthetic captures).

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

/// Classic pcap magic (microsecond resolution, big-endian writer).
pub const PCAP_MAGIC: u32 = 0xa1_b2_c3_d4;
/// LINKTYPE_ETHERNET.
pub const LINKTYPE_ETHERNET: u32 = 1;

const GLOBAL_HEADER_LEN: usize = 24;

/// A pcap sink bound to one file.
pub struct PcapWriter {
    w: io::BufWriter<std::fs::File>,
    packets: u64,
    bytes_written: u64,
    max_bytes: u64,
    ip_id: u16,
    pub path: std::path::PathBuf,
    /// Set once the file size cap is reached; further packets are dropped.
    pub stopped: bool,
}

impl PcapWriter {
    /// Creates (truncates) the pcap file and writes the 24-byte global
    /// header.
    pub fn create(path: &Path, max_file_bytes: u64) -> io::Result<Self> {
        let mut f = std::fs::File::create(path)?;
        let mut hdr = Vec::with_capacity(GLOBAL_HEADER_LEN);
        hdr.extend_from_slice(&PCAP_MAGIC.to_be_bytes());
        hdr.extend_from_slice(&2u16.to_be_bytes()); // version major
        hdr.extend_from_slice(&4u16.to_be_bytes()); // version minor
        hdr.extend_from_slice(&0i32.to_be_bytes()); // thiszone
        hdr.extend_from_slice(&0u32.to_be_bytes()); // sigfigs
        hdr.extend_from_slice(&65_535u32.to_be_bytes()); // snaplen
        hdr.extend_from_slice(&LINKTYPE_ETHERNET.to_be_bytes());
        f.write_all(&hdr)?;
        Ok(PcapWriter {
            w: io::BufWriter::new(f),
            packets: 0,
            bytes_written: GLOBAL_HEADER_LEN as u64,
            max_bytes: max_file_bytes.max(GLOBAL_HEADER_LEN as u64 + 64),
            ip_id: 0x1,
            path: path.to_path_buf(),
            stopped: false,
        })
    }

    /// Writes one UDP datagram observed at `ts_us` (unix microseconds).
    pub fn write_udp(
        &mut self,
        ts_us: i64,
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        let frame_len = 14 + 20 + 8 + payload.len();
        if self.bytes_written + frame_len as u64 > self.max_bytes {
            self.stopped = true;
            tracing::warn!(
                path = %self.path.display(),
                "pcap size cap reached; capture stopped for this file"
            );
            return Ok(());
        }
        let (src_ip, src_port) = as_v4(src);
        let (dst_ip, dst_port) = as_v4(dst);

        // --- pcap record header ---
        let ts_sec = (ts_us / 1_000_000) as u32;
        let ts_usec = (ts_us % 1_000_000) as u32;
        self.w.write_all(&ts_sec.to_be_bytes())?;
        self.w.write_all(&ts_usec.to_be_bytes())?;
        self.w.write_all(&(frame_len as u32).to_be_bytes())?; // incl_len
        self.w.write_all(&(frame_len as u32).to_be_bytes())?; // orig_len

        // --- Ethernet (14 B): locally-administered MACs derived from IPs ---
        self.w.write_all(&mac_for(dst_ip))?;
        self.w.write_all(&mac_for(src_ip))?;
        self.w.write_all(&0x0800u16.to_be_bytes())?; // IPv4

        // --- IPv4 (20 B), checksum 0, DF set, TTL 64 ---
        let total_len = (20 + 8 + payload.len()) as u16;
        self.ip_id = self.ip_id.wrapping_add(1);
        self.w.write_all(&[0x45, 0x00])?; // v4, IHL 5, DSCP 0
        self.w.write_all(&total_len.to_be_bytes())?;
        self.w.write_all(&self.ip_id.to_be_bytes())?;
        self.w.write_all(&0x4000u16.to_be_bytes())?; // DF, no fragment
        self.w.write_all(&[64, 17])?; // TTL, proto UDP
        self.w.write_all(&[0, 0])?; // checksum 0 (accepted by Wireshark)
        self.w.write_all(&src_ip.octets())?;
        self.w.write_all(&dst_ip.octets())?;

        // --- UDP (8 B), checksum 0 ("not computed", legal over IPv4) ---
        self.w.write_all(&src_port.to_be_bytes())?;
        self.w.write_all(&dst_port.to_be_bytes())?;
        self.w.write_all(&(8 + payload.len() as u16).to_be_bytes())?;
        self.w.write_all(&0u16.to_be_bytes())?;

        self.w.write_all(payload)?;
        self.packets += 1;
        self.bytes_written += frame_len as u64;
        Ok(())
    }

    pub fn flush(&mut self) {
        let _ = self.w.flush();
    }

    /// (packets written, file bytes including the global header)
    pub fn stats(&self) -> (u64, u64) {
        (self.packets, self.bytes_written)
    }
}

fn as_v4(a: SocketAddr) -> (Ipv4Addr, u16) {
    match a {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        SocketAddr::V6(v6) => (v6.ip().to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED), v6.port()),
    }
}

fn mac_for(ip: Ipv4Addr) -> [u8; 6] {
    let o = ip.octets();
    [0x02, o[0], o[1], o[2], o[3], 0x01]
}

/// One decoded frame from [`read_frames`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub ts_us: i64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// Minimal classic-pcap reader (ENOUGH for `zrtc capture dump` and tests):
/// yields UDP frames as (ts, src, dst, payload).
pub fn read_frames(path: &Path) -> io::Result<Vec<RawFrame>> {
    let mut data = Vec::new();
    std::fs::File::open(path)?.read_to_end(&mut data)?;
    if data.len() < GLOBAL_HEADER_LEN || u32::from_be_bytes([data[0], data[1], data[2], data[3]]) != PCAP_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a classic pcap (wrong magic)"));
    }
    let mut out = Vec::new();
    let mut pos = GLOBAL_HEADER_LEN;
    while pos + 16 <= data.len() {
        let ts_sec = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as i64;
        let ts_usec = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as i64;
        let incl = u32::from_be_bytes(data[pos + 8..pos + 12].try_into().unwrap()) as usize;
        pos += 16;
        if pos + incl > data.len() {
            break; // truncated tail
        }
        let frame = &data[pos..pos + incl];
        pos += incl;
        if let Some(f) = decode_udp_frame(ts_sec * 1_000_000 + ts_usec, frame) {
            out.push(f);
        }
    }
    Ok(out)
}

fn decode_udp_frame(ts_us: i64, frame: &[u8]) -> Option<RawFrame> {
    if frame.len() < 14 + 20 + 8 || u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
        return None;
    }
    let ip = &frame[14..];
    if ip[0] >> 4 != 4 || ip[9] != 17 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ip.len() < ihl + 8 {
        return None;
    }
    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let udp = &ip[ihl..];
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    let ulen = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let payload_len = ulen.saturating_sub(8).min(udp.len() - 8);
    Some(RawFrame {
        ts_us,
        src: SocketAddr::from((src_ip, sport)),
        dst: SocketAddr::from((dst_ip, dport)),
        payload: udp[8..8 + payload_len].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_roundtrip() {
        let dir = std::env::temp_dir().join(format!("observ-pcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.pcap");
        let src: SocketAddr = "10.1.2.3:5060".parse().unwrap();
        let dst: SocketAddr = "10.9.8.7:5070".parse().unwrap();
        let payload = b"INVITE sip:1000@x SIP/2.0\r\n\r\n";
        {
            let mut w = PcapWriter::create(&path, 64 * 1024).unwrap();
            w.write_udp(1_700_000_000_000_123, src, dst, payload).unwrap();
            w.write_udp(1_700_000_000_100_000, dst, src, b"\x80\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01payload").unwrap();
            w.flush();
            assert_eq!(w.stats().0, 2);
            assert!(!w.stopped);
        }
        let frames = read_frames(&path).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].src, src);
        assert_eq!(frames[0].dst, dst);
        assert_eq!(frames[0].payload, payload.to_vec());
        assert_eq!(frames[0].ts_us, 1_700_000_000_000_123);
        assert_eq!(frames[1].src, dst);

        // Wireshark-native decodability invariants: ethertype IPv4,
        // proto UDP, DF bit, TTL 64, zero checksums.
        let raw = std::fs::read(&path).unwrap();
        // skip the 24-byte global header and the 16-byte record header
        let frame = &raw[24 + 16..24 + 16 + 14 + 20 + 8 + payload.len()];
        assert_eq!(&frame[12..14], &0x0800u16.to_be_bytes());
        let ip = &frame[14..];
        assert_eq!(ip[0], 0x45);
        assert_eq!(&ip[6..8], &0x4000u16.to_be_bytes(), "DF set");
        assert_eq!(ip[8], 64);
        assert_eq!(ip[10..12], [0, 0], "ip checksum 0");
        assert_eq!(&udp_of(ip)[6..8], &[0, 0], "udp checksum 0");

        std::fs::remove_dir_all(&dir).ok();
    }

    fn udp_of(ip: &[u8]) -> &[u8] {
        let ihl = (ip[0] & 0x0f) as usize * 4;
        &ip[ihl..]
    }

    #[test]
    fn size_cap_stops_writing() {
        let dir = std::env::temp_dir().join(format!("observ-pcap-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.pcap");
        let mut w = PcapWriter::create(&path, 500).unwrap();
        let big = vec![0u8; 400];
        w.write_udp(1, "127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap(), &big).unwrap();
        w.write_udp(2, "127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap(), &big).unwrap();
        assert!(w.stopped, "cap reached after exceeding max bytes");
        assert_eq!(w.stats().0, 1, "post-cap packets dropped");
        std::fs::remove_dir_all(&dir).ok();
    }
}
