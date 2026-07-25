//! Length-prefixed message framing.
//!
//! Chrome/Firefox native messaging prefixes each JSON document with its length
//! as a 32-bit integer in **native** byte order. The same framing is reused for
//! the CLI-to-service socket so one codec covers both hops.

use std::io::{self, Read, Write};

/// Reject absurd lengths rather than trying to allocate them. Real messages are
/// a few kilobytes; the helper's own limit is far below this.
pub const MAX_FRAME_LEN: usize = 32 * 1024 * 1024;

/// Write `body` with its length prefix, then flush.
pub fn write_frame<W: Write>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame is too large to send",
        ));
    }
    let length = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame is too large to send"))?;
    writer.write_all(&length.to_ne_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

/// Read one frame. `Ok(None)` means the peer closed cleanly between frames.
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }

    let length = u32::from_ne_bytes(header) as usize;
    if length > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {length} exceeds the {MAX_FRAME_LEN}-byte limit"),
        ));
    }

    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"{\"cmd\":14}").unwrap();
        write_frame(&mut buffer, b"").unwrap();

        let mut cursor = io::Cursor::new(buffer);
        assert_eq!(read_frame(&mut cursor).unwrap().unwrap(), b"{\"cmd\":14}");
        assert_eq!(read_frame(&mut cursor).unwrap().unwrap(), b"");
        assert_eq!(read_frame(&mut cursor).unwrap(), None);
    }

    #[test]
    fn header_uses_native_byte_order() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"ab").unwrap();
        assert_eq!(&buffer[..4], &2u32.to_ne_bytes());
        assert_eq!(&buffer[4..], b"ab");
    }

    #[test]
    fn truncated_body_is_an_error_not_a_clean_eof() {
        let mut buffer = 8u32.to_ne_bytes().to_vec();
        buffer.extend_from_slice(b"abc");
        let error = read_frame(&mut io::Cursor::new(buffer)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversized_length_is_rejected_before_allocating() {
        let buffer = u32::MAX.to_ne_bytes().to_vec();
        let error = read_frame(&mut io::Cursor::new(buffer)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
