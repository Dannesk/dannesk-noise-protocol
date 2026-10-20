//! The socket both ends speak, over any byte stream.

use crate::handshake::{
    Error, Initiator, KEY_LEN, MAX_HANDSHAKE_PAYLOAD, MAX_TRANSPORT_PAYLOAD, Receiver, Responder,
    Sender, StaticKey, TAG_LEN,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

pub const VERSION: u8 = 0x01;
const PROLOGUE: &[u8] = b"dannesk-noise-socket";

fn prologue(key_id: u8) -> Vec<u8> {
    [PROLOGUE, &[VERSION, key_id]].concat()
}

#[derive(Debug)]
pub enum StreamError {
    Io(std::io::Error),
    Noise(Error),
    Version(u8),
    UnknownKey(u8),
    FrameTooLong(usize),
    Record,
    Closed,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Io(e) => write!(f, "i/o: {e}"),
            StreamError::Noise(e) => write!(f, "noise: {e}"),
            StreamError::Version(v) => write!(f, "socket version {v} not spoken"),
            StreamError::UnknownKey(id) => write!(f, "key {id} not held"),
            StreamError::FrameTooLong(n) => write!(f, "frame of {n} bytes over the limit"),
            StreamError::Record => f.write_str("record too short for a message"),
            StreamError::Closed => f.write_str("closed by the peer"),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<std::io::Error> for StreamError {
    fn from(e: std::io::Error) -> Self {
        StreamError::Io(e)
    }
}

impl From<Error> for StreamError {
    fn from(e: Error) -> Self {
        StreamError::Noise(e)
    }
}

pub struct Reader<R> {
    io: R,
    recv: Receiver,
    pending: Vec<u8>,
    max_frame: usize,
}

pub struct Writer<W> {
    io: W,
    send: Sender,
}


pub async fn connect<T: AsyncRead + AsyncWrite + Unpin>(
    mut io: T,
    server: &[u8; KEY_LEN],
    key_id: u8,
    first_frames: &[&[u8]],
    max_frame: usize,
) -> Result<(Reader<ReadHalf<T>>, Writer<WriteHalf<T>>), StreamError> {
    let payload = handshake_payload(first_frames)?;
    let (initiator, message) = Initiator::new(server, &prologue(key_id)).write_message(&payload)?;
    let mut out = Vec::with_capacity(2 + 2 + message.len());
    out.extend_from_slice(&[VERSION, key_id]);
    out.extend_from_slice(&(message.len() as u16).to_be_bytes());
    out.extend_from_slice(&message);
    io.write_all(&out).await?;
    let reply = read_record(&mut io).await?;
    let (session, pending) = initiator.read_message(&reply)?;
    let (send, recv) = session.split();
    let (r, w) = tokio::io::split(io);
    Ok((Reader { io: r, recv, pending, max_frame }, Writer { io: w, send }))
}


pub async fn accept<T: AsyncRead + AsyncWrite + Unpin>(
    mut io: T,
    keys: &[(u8, StaticKey)],
    first_frames: &[&[u8]],
    max_frame: usize,
) -> Result<(Reader<ReadHalf<T>>, Writer<WriteHalf<T>>), StreamError> {
    let mut opener = [0u8; 2];
    io.read_exact(&mut opener).await?;
    if opener[0] != VERSION {
        return Err(StreamError::Version(opener[0]));
    }
    let key_id = opener[1];
    let Some((_, key)) = keys.iter().find(|(id, _)| *id == key_id) else {
        return Err(StreamError::UnknownKey(key_id));
    };
    let message = read_record(&mut io).await?;
    let (responder, pending) = Responder::new(key, &prologue(key_id)).read_message(&message)?;
    let payload = handshake_payload(first_frames)?;
    let (session, reply) = responder.write_message(&payload)?;
    write_record(&mut io, &reply).await?;
    let (send, recv) = session.split();
    let (r, w) = tokio::io::split(io);
    Ok((Reader { io: r, recv, pending, max_frame }, Writer { io: w, send }))
}

impl<R: AsyncRead + Unpin> Reader<R> {

    pub async fn recv_frame(&mut self) -> Result<Vec<u8>, StreamError> {
        loop {
            if let Some(frame) = take_frame(&mut self.pending, self.max_frame)? {
                return Ok(frame);
            }
            let record = match read_record(&mut self.io).await {
                Err(StreamError::Closed) if !self.pending.is_empty() => {
                    return Err(StreamError::Io(std::io::ErrorKind::UnexpectedEof.into()));
                }
                other => other?,
            };
            let plaintext = self.recv.decrypt(&record)?;
            self.pending.extend_from_slice(&plaintext);
        }
    }
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub async fn send_frame(&mut self, frame: &[u8]) -> Result<(), StreamError> {
        let mut plaintext = Vec::with_capacity(4 + frame.len());
        push_frame(&mut plaintext, frame)?;
        let records = plaintext.len().div_ceil(MAX_TRANSPORT_PAYLOAD);
        let mut out = Vec::with_capacity(plaintext.len() + records * (2 + TAG_LEN));
        for chunk in plaintext.chunks(MAX_TRANSPORT_PAYLOAD) {
            let message = self.send.encrypt(chunk)?;
            out.extend_from_slice(&(message.len() as u16).to_be_bytes());
            out.extend_from_slice(&message);
        }
        Ok(self.io.write_all(&out).await?)
    }

    pub async fn shutdown(&mut self) -> Result<(), StreamError> {
        Ok(self.io.shutdown().await?)
    }
}


async fn read_record<R: AsyncRead + Unpin>(io: &mut R) -> Result<Vec<u8>, StreamError> {
    let mut header = [0u8; 2];
    if io.read(&mut header[..1]).await? == 0 {
        return Err(StreamError::Closed);
    }
    io.read_exact(&mut header[1..]).await?;
    let len = u16::from_be_bytes(header) as usize;
    if len < TAG_LEN {
        return Err(StreamError::Record);
    }
    let mut record = vec![0u8; len];
    io.read_exact(&mut record).await?;
    Ok(record)
}

async fn write_record<W: AsyncWrite + Unpin>(io: &mut W, message: &[u8]) -> Result<(), StreamError> {
    let mut out = Vec::with_capacity(2 + message.len());
    out.extend_from_slice(&(message.len() as u16).to_be_bytes());
    out.extend_from_slice(message);
    Ok(io.write_all(&out).await?)
}

fn push_frame(buf: &mut Vec<u8>, frame: &[u8]) -> Result<(), StreamError> {
    let len = u32::try_from(frame.len()).map_err(|_| StreamError::FrameTooLong(frame.len()))?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(frame);
    Ok(())
}

fn handshake_payload(frames: &[&[u8]]) -> Result<Vec<u8>, StreamError> {
    let mut payload = Vec::new();
    for frame in frames {
        push_frame(&mut payload, frame)?;
    }
    if payload.len() > MAX_HANDSHAKE_PAYLOAD {
        return Err(StreamError::Noise(Error::TooLong));
    }
    Ok(payload)
}

fn take_frame(pending: &mut Vec<u8>, max_frame: usize) -> Result<Option<Vec<u8>>, StreamError> {
    if pending.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([pending[0], pending[1], pending[2], pending[3]]) as usize;
    if len > max_frame {
        return Err(StreamError::FrameTooLong(len));
    }
    if pending.len() < 4 + len {
        return Ok(None);
    }
    let frame = pending[4..4 + len].to_vec();
    pending.drain(..4 + len);
    Ok(Some(frame))
}

// ───────────────────────── tests ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    const MAX: usize = 1 << 20;
    const KEY_ID: u8 = 7;

    type End = (Reader<ReadHalf<DuplexStream>>, Writer<WriteHalf<DuplexStream>>);

    async fn pair(first_app: &[&[u8]], first_proxy: &[&[u8]]) -> (End, End) {
        let key = StaticKey::generate();
        let public = key.public();
        let keys = vec![(KEY_ID, key)];
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (app, proxy) = tokio::join!(
            connect(a, &public, KEY_ID, first_app, MAX),
            accept(b, &keys, first_proxy, MAX),
        );
        (app.unwrap(), proxy.unwrap())
    }

    #[tokio::test]
    async fn first_frames_arrive_first_both_ways() {
        let ((mut app_r, mut app_w), (mut proxy_r, mut proxy_w)) =
            pair(&[b"hello", b"ask"], &[b"link"]).await;
        assert_eq!(proxy_r.recv_frame().await.unwrap(), b"hello");
        assert_eq!(proxy_r.recv_frame().await.unwrap(), b"ask");
        assert_eq!(app_r.recv_frame().await.unwrap(), b"link");
        app_w.send_frame(b"after").await.unwrap();
        assert_eq!(proxy_r.recv_frame().await.unwrap(), b"after");
        proxy_w.send_frame(&[]).await.unwrap();
        assert_eq!(app_r.recv_frame().await.unwrap(), b"");
    }

    #[tokio::test]
    async fn a_frame_longer_than_a_record_crosses_records() {
        let ((mut app_r, _app_w), (_proxy_r, mut proxy_w)) = pair(&[], &[]).await;
        let big: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        let (sent, received) = tokio::join!(proxy_w.send_frame(&big), app_r.recv_frame());
        sent.unwrap();
        assert_eq!(received.unwrap(), big);
        proxy_w.send_frame(b"next").await.unwrap();
        assert_eq!(app_r.recv_frame().await.unwrap(), b"next");
    }

    #[tokio::test]
    async fn a_frame_over_the_limit_is_refused_at_its_header() {
        let key = StaticKey::generate();
        let public = key.public();
        let keys = vec![(KEY_ID, key)];
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (app, proxy) = tokio::join!(connect(a, &public, KEY_ID, &[], 1024), accept(b, &keys, &[], MAX));
        let (mut app_r, _app_w) = app.unwrap();
        let (_proxy_r, mut proxy_w) = proxy.unwrap();
        let (sent, received) = tokio::join!(proxy_w.send_frame(&[0u8; 1025]), app_r.recv_frame());
        sent.unwrap();
        assert!(matches!(received, Err(StreamError::FrameTooLong(1025))));
    }

    #[tokio::test]
    async fn a_close_between_frames_is_orderly_and_inside_one_is_not() {
        let ((mut app_r, _app_w), (_proxy_r, mut proxy_w)) = pair(&[], &[]).await;
        proxy_w.send_frame(b"last").await.unwrap();
        proxy_w.shutdown().await.unwrap();
        assert_eq!(app_r.recv_frame().await.unwrap(), b"last");
        assert!(matches!(app_r.recv_frame().await, Err(StreamError::Closed)));

        let ((mut app_r, _app_w), (_proxy_r, proxy_w)) = pair(&[], &[]).await;
        let mut proxy_w = proxy_w;
        let frame_start = {
            let mut plaintext = Vec::new();
            push_frame(&mut plaintext, &[1u8; 10]).unwrap();
            plaintext.truncate(8);
            let message = proxy_w.send.encrypt(&plaintext).unwrap();
            let mut out = (message.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&message);
            out
        };
        proxy_w.io.write_all(&frame_start).await.unwrap();
        proxy_w.shutdown().await.unwrap();
        assert!(matches!(app_r.recv_frame().await, Err(StreamError::Io(_))));
    }

    #[tokio::test]
    async fn the_opener_is_checked() {
        let key = StaticKey::generate();
        let keys = vec![(KEY_ID, key)];
        let (mut a, b) = tokio::io::duplex(1024);
        a.write_all(&[VERSION + 1, KEY_ID]).await.unwrap();
        assert!(matches!(accept(b, &keys, &[], MAX).await, Err(StreamError::Version(2))));

        let (mut a, b) = tokio::io::duplex(1024);
        a.write_all(&[VERSION, KEY_ID + 1]).await.unwrap();
        assert!(matches!(accept(b, &keys, &[], MAX).await, Err(StreamError::UnknownKey(8))));
    }

    #[tokio::test]
    async fn the_wrong_server_key_fails_both_ends() {
        let key = StaticKey::generate();
        let other = StaticKey::generate().public();
        let keys = vec![(KEY_ID, key)];
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (app, proxy) = tokio::join!(connect(a, &other, KEY_ID, &[b"hello"], MAX), accept(b, &keys, &[], MAX));
        assert!(matches!(proxy, Err(StreamError::Noise(Error::Decrypt))));
        assert!(matches!(app, Err(StreamError::Closed)));
    }

    #[tokio::test]
    async fn the_wire_begins_with_the_opener_and_nothing_readable() {
        let key = StaticKey::generate();
        let public = key.public();
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let hello = b"{\"type\":\"hello\"}";
        let (_, wire) = tokio::join!(
            async {
                let _ = connect(a, &public, KEY_ID, &[hello], MAX).await;
            },
            async {
                let mut wire = vec![0u8; 2 + 2 + KEY_LEN + 4 + hello.len() + TAG_LEN];
                b.read_exact(&mut wire).await.unwrap();
                drop(b);
                wire
            }
        );
        assert_eq!(&wire[..2], &[VERSION, KEY_ID]);
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]) as usize, wire.len() - 4);
        assert!(!wire.windows(hello.len()).any(|w| w == hello));
        assert!(!wire.windows(4).any(|w| w == b"type"));
    }
}
