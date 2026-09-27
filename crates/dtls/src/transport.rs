//! Datagram queue transport for driving OpenSSL DTLS over UDP.
//!
//! DTLS records must be delivered with datagram boundaries intact, so the
//! transport implements [`std::io::Read`] such that each call returns
//! exactly one queued datagram (mapping "queue empty" to `WouldBlock`,
//! which the OpenSSL state machine sees as `WANT_READ`), and
//! [`std::io::Write`] such that each call is one outbound datagram.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Result as IoResult, Write};

/// A bidirectional datagram queue implementing `Read + Write`.
pub struct QueueIo {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    /// Bytes lost from the current outbound datagram when the writer is
    /// called with a short buffer (never happens with OpenSSL).
    max_datagram: usize,
}

impl QueueIo {
    pub fn new() -> Self {
        QueueIo {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            max_datagram: 1500,
        }
    }

    /// Queue one received datagram for the OpenSSL state machine.
    pub fn push_inbound(&mut self, datagram: Vec<u8>) {
        self.inbound.push_back(datagram);
    }

    /// Drain all datagrams the state machine produced (one flight).
    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.outbound.drain(..).collect()
    }

    pub fn is_inbound_empty(&self) -> bool {
        self.inbound.is_empty()
    }

    /// Largest datagram seen outbound (for MTU diagnostics).
    pub fn max_outbound_datagram(&self) -> usize {
        self.max_datagram
    }
}

impl Default for QueueIo {
    fn default() -> Self {
        Self::new()
    }
}

impl Read for QueueIo {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match self.inbound.pop_front() {
            Some(datagram) => {
                let n = datagram.len().min(buf.len());
                buf[..n].copy_from_slice(&datagram[..n]);
                Ok(n)
            }
            None => Err(std::io::Error::new(ErrorKind::WouldBlock, "no datagram")),
        }
    }
}

impl Write for QueueIo {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if buf.len() > self.max_datagram {
            self.max_datagram = buf.len();
        }
        self.outbound.push_back(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_boundaries_preserved() {
        let mut io = QueueIo::new();
        io.push_inbound(vec![1, 2, 3]);
        io.push_inbound(vec![4, 5]);
        let mut buf = [0u8; 64];
        assert_eq!(io.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], &[1, 2, 3]);
        assert_eq!(io.read(&mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &[4, 5]);
        assert_eq!(io.read(&mut buf).unwrap_err().kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn writes_are_datagrams() {
        let mut io = QueueIo::new();
        io.write_all(&[9, 9, 9]).unwrap();
        io.write_all(&[7]).unwrap();
        let out = io.drain_outbound();
        assert_eq!(out, vec![vec![9, 9, 9], vec![7]]);
        assert_eq!(io.drain_outbound(), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn short_read_buffer_truncates_safely() {
        let mut io = QueueIo::new();
        io.push_inbound(vec![1, 2, 3, 4, 5]);
        let mut buf = [0u8; 2];
        assert_eq!(io.read(&mut buf).unwrap(), 2);
    }
}
