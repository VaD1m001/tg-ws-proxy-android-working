use crate::config::{log_debug, log_warn, STATS};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

const CLIENT_RANDOM_OFFSET: usize = 11;
const CLIENT_RANDOM_LEN: usize = 32;
const SESSION_ID_OFFSET: usize = 44;
const SESSION_ID_LEN: usize = 32;

const TIMESTAMP_TOLERANCE: i64 = 120;
const TLS_APPDATA_MAX: usize = 16384;

const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;

const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519MLKEM768: u16 = 0x11ec;

const X25519_KEY_LEN: usize = 32;
const X25519MLKEM768_CLIENT_SHARE_LEN: usize = 1216;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

// TLS 1.3 suites in the order a typical server picks them from the client list
const CIPHER_PREFERENCE: [u16; 3] = [0x1301, 0x1303, 0x1302];

// Without a site profile stay near the 64-byte record that telemt passed DPI with.
const FALLBACK_APPDATA_MIN: usize = 64;
const FALLBACK_APPDATA_MAX: usize = 160;

const SERVER_HELLO_DELAY_MIN_MS: u64 = 8;
const SERVER_HELLO_DELAY_MAX_MS: u64 = 24;

const READ_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_RECORD_TIMEOUT: Duration = Duration::from_secs(10);
const MASKING_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

const SH_RANDOM_OFF: usize = 11;

type HmacSha256 = Hmac<Sha256>;

#[derive(Default)]
pub struct ClientHelloInfo {
    cipher_suites: HashSet<u16>,
    key_shares: HashMap<u16, usize>,
}

pub struct FakeTlsStream {
    pub read: Box<dyn AsyncRead + Send + Unpin>,
    pub write: Box<dyn AsyncWrite + Send + Unpin>,
}

fn be16(data: &[u8], pos: usize) -> Option<usize> {
    if pos + 2 > data.len() {
        return None;
    }
    Some(u16::from_be_bytes([data[pos], data[pos + 1]]) as usize)
}

/// Extract offered cipher suites and key_share groups from a ClientHello.
/// Returns empty info on malformed input so the caller falls back to the
/// plain X25519 / TLS_AES_128_GCM_SHA256 answer.
pub fn parse_client_hello(data: &[u8]) -> ClientHelloInfo {
    let mut info = ClientHelloInfo::default();
    if data.len() < 43 {
        return info;
    }

    let mut pos = 5 + 4 + 2 + CLIENT_RANDOM_LEN;
    let sid_len = data[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > data.len() {
        return info;
    }

    let suites_len = match be16(data, pos) {
        Some(v) => v,
        None => return info,
    };
    pos += 2;
    let suites_end = pos + suites_len;
    if suites_end > data.len() {
        return info;
    }
    while pos + 2 <= suites_end {
        info.cipher_suites
            .insert(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }
    pos = suites_end;

    if pos >= data.len() {
        return info;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > data.len() {
        return info;
    }

    let ext_total = match be16(data, pos) {
        Some(v) => v,
        None => return info,
    };
    pos += 2;
    let ext_end = std::cmp::min(pos + ext_total, data.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == EXT_KEY_SHARE && pos + 2 <= ext_end {
            let shares_len = be16(data, pos).unwrap_or(0);
            let shares_end = std::cmp::min(pos + 2 + shares_len, ext_end);
            let mut off = pos + 2;
            while off + 4 <= shares_end {
                let group = u16::from_be_bytes([data[off], data[off + 1]]);
                let key_len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
                off += 4 + key_len;
                if off <= shares_end {
                    info.key_shares.entry(group).or_insert(key_len);
                }
            }
        }

        pos += ext_len;
    }

    info
}

fn x25519_public_key() -> [u8; X25519_KEY_LEN] {
    // The client never derives keys from the fake handshake; keep the value
    // shape-valid (field element below 2^255) as the original core does.
    let mut key = [0u8; X25519_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key[X25519_KEY_LEN - 1] &= 0x7f;
    key
}

fn select_cipher_suite(info: &ClientHelloInfo) -> u16 {
    for suite in CIPHER_PREFERENCE {
        if info.cipher_suites.contains(&suite) {
            return suite;
        }
    }
    CIPHER_PREFERENCE[0]
}

fn server_key_share(info: &ClientHelloInfo) -> (u16, Vec<u8>) {
    // Mirror the hybrid post-quantum group when the client offers it, as
    // current browsers and servers do; the client never derives keys from it.
    if info.key_shares.get(&GROUP_X25519MLKEM768) == Some(&X25519MLKEM768_CLIENT_SHARE_LEN) {
        let mut key = vec![0u8; MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key[..MLKEM768_CIPHERTEXT_LEN]);
        key[MLKEM768_CIPHERTEXT_LEN..].copy_from_slice(&x25519_public_key());
        return (GROUP_X25519MLKEM768, key);
    }
    (GROUP_X25519, x25519_public_key().to_vec())
}

fn build_server_hello(
    secret: &[u8],
    client_random: &[u8; 32],
    session_id: &[u8],
    info: &ClientHelloInfo,
) -> Vec<u8> {
    let (group, key_exchange) = server_key_share(info);

    let mut extensions = Vec::with_capacity(64 + key_exchange.len());
    extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
    extensions.extend_from_slice(&2u16.to_be_bytes());
    extensions.extend_from_slice(&0x0304u16.to_be_bytes());
    extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
    extensions.extend_from_slice(&((4 + key_exchange.len()) as u16).to_be_bytes());
    extensions.extend_from_slice(&group.to_be_bytes());
    extensions.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key_exchange);

    let cipher = select_cipher_suite(info);
    let mut body = Vec::with_capacity(96 + session_id.len() + extensions.len());
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0x00);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut message = Vec::with_capacity(4 + body.len());
    message.push(0x02);
    let body_len = body.len() as u32;
    message.push((body_len >> 16) as u8);
    message.push((body_len >> 8) as u8);
    message.push(body_len as u8);
    message.extend_from_slice(&body);

    let mut response = Vec::with_capacity(5 + message.len() + 6 + 5 + FALLBACK_APPDATA_MAX);
    response.push(TLS_RECORD_HANDSHAKE);
    response.extend_from_slice(&[0x03, 0x03]);
    response.extend_from_slice(&(message.len() as u16).to_be_bytes());
    response.extend_from_slice(&message);
    response.extend_from_slice(&CCS_FRAME);

    let rand_len = rand::thread_rng()
        .gen_range(FALLBACK_APPDATA_MIN..=FALLBACK_APPDATA_MAX);
    let mut encrypted_data = vec![0u8; rand_len];
    rand::thread_rng().fill_bytes(&mut encrypted_data);
    response.push(TLS_RECORD_APPDATA);
    response.push(0x03);
    response.push(0x03);
    response.extend_from_slice(&(rand_len as u16).to_be_bytes());
    response.extend_from_slice(&encrypted_data);

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(client_random);
    mac.update(&response);
    let server_random = mac.finalize().into_bytes();

    let mut final_bytes = response;
    final_bytes[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&server_random);
    final_bytes
}

fn verify_client_hello(data: &[u8], secret: &[u8]) -> Option<([u8; 32], Vec<u8>, i64)> {
    if data.len() < 43 {
        return None;
    }
    if data[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }
    if data[5] != 0x01 {
        return None;
    }

    let mut client_random = [0u8; 32];
    client_random
        .copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    for b in &mut zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN] {
        *b = 0;
    }

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();

    if expected[..28] != client_random[..28] {
        return None;
    }

    let mut ts_bytes = [0u8; 4];
    for i in 0..4 {
        ts_bytes[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_bytes) as i64;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if (now - timestamp).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = Vec::new();
    if data.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id
            .extend_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }

    Some((client_random, session_id, timestamp))
}

fn wrap_tls_record(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / TLS_APPDATA_MAX + 1));
    let mut offset = 0;
    while offset < data.len() {
        let end = std::cmp::min(offset + TLS_APPDATA_MAX, data.len());
        let chunk = &data[offset..end];
        out.push(TLS_RECORD_APPDATA);
        out.push(0x03);
        out.push(0x03);
        out.push((chunk.len() >> 8) as u8);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
        offset = end;
    }
    out
}

struct TlsRecordReader {
    inner: ReadHalf<TcpStream>,
    buf: Vec<u8>,
    pos: usize,
    read_left: usize,
}

impl TlsRecordReader {
    fn new(inner: ReadHalf<TcpStream>) -> Self {
        TlsRecordReader {
            inner,
            buf: Vec::new(),
            pos: 0,
            read_left: 0,
        }
    }

    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn next_payload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            loop {
                if self.read_left > 0 {
                    let want = std::cmp::min(self.read_left, 16384);
                    let mut chunk = vec![0u8; want];
                    let n = self.inner.read(&mut chunk).await?;
                    if n == 0 {
                        return Ok(Vec::new());
                    }
                    chunk.truncate(n);
                    self.read_left -= n;
                    return Ok(chunk);
                }

                let mut hdr = [0u8; 5];
                self.inner.read_exact(&mut hdr).await?;
                let rtype = hdr[0];
                let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;

                if rtype == TLS_RECORD_CCS {
                    if rec_len > 0 {
                        let mut junk = vec![0u8; rec_len];
                        self.inner.read_exact(&mut junk).await?;
                    }
                    continue;
                }

                if rtype != TLS_RECORD_APPDATA {
                    return Ok(Vec::new());
                }

                let want = std::cmp::min(rec_len, 65536);
                let mut chunk = vec![0u8; want];
                let n = self.inner.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(Vec::new());
                }
                chunk.truncate(n);
                if rec_len > n {
                    self.read_left = rec_len - n;
                }
                return Ok(chunk);
            }
        })
    }
}

impl AsyncRead for TlsRecordReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            let avail = this.buf.len() - this.pos;
            if avail > 0 {
                let n = std::cmp::min(avail, buf.remaining());
                let src = &this.buf[this.pos..this.pos + n];
                buf.put_slice(src);
                this.pos += n;
                if this.pos == this.buf.len() {
                    this.buf.clear();
                    this.pos = 0;
                }
                return std::task::Poll::Ready(Ok(()));
            }

            this.compact();
            let polled = {
                let mut fut = this.next_payload();
                Pin::new(&mut fut).poll(cx)
            };
            match polled {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Err(
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "faketls eof")
                        } else {
                            e
                        },
                    ))
                }
                std::task::Poll::Ready(Ok(payload)) => {
                    if payload.is_empty() {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    this.buf = payload;
                    this.pos = 0;
                }
            }
        }
    }
}

struct TlsRecordWriter {
    inner: WriteHalf<TcpStream>,
}

impl TlsRecordWriter {
    fn new(inner: WriteHalf<TcpStream>) -> Self {
        TlsRecordWriter { inner }
    }
}

impl AsyncWrite for TlsRecordWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let wrapped = wrap_tls_record(buf);
        match Pin::new(&mut this.inner).poll_write(cx, &wrapped) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(n)) => {
                std::task::Poll::Ready(Ok(if n >= buf.len() { buf.len() } else { n }))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub async fn server_handshake(
    mut conn: TcpStream,
    first: u8,
    secret: &[u8],
    masking: &str,
    label: &str,
) -> Option<FakeTlsStream> {
    let mut hdr_rest = [0u8; 4];
    match tokio::time::timeout(READ_HANDSHAKE_TIMEOUT, conn.read_exact(&mut hdr_rest)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record header", label));
            return None;
        }
    }

    let mut tls_header = [0u8; 5];
    tls_header[0] = first;
    tls_header[1..5].copy_from_slice(&hdr_rest);
    let record_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;

    let mut body = vec![0u8; record_len];
    match tokio::time::timeout(READ_RECORD_TIMEOUT, conn.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        _ => {
            log_debug(&format!("[{}] incomplete TLS record body", label));
            return None;
        }
    }

    let mut client_hello = Vec::with_capacity(5 + record_len);
    client_hello.extend_from_slice(&tls_header);
    client_hello.extend_from_slice(&body);

    match verify_client_hello(&client_hello, secret) {
        Some((client_random, session_id, ts)) => {
            log_debug(&format!("[{}] Fake TLS handshake ok (ts={})", label, ts));
            let info = parse_client_hello(&client_hello);
            let server_hello = build_server_hello(secret, &client_random, &session_id, &info);
            let delay_ms = {
                let mut rng = rand::thread_rng();
                rng.gen_range(SERVER_HELLO_DELAY_MIN_MS..=SERVER_HELLO_DELAY_MAX_MS)
            };
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            if conn.write_all(&server_hello).await.is_err() {
                return None;
            }
            let _ = conn.flush().await;

            let (r, w) = tokio::io::split(conn);
            Some(FakeTlsStream {
                read: Box::new(TlsRecordReader::new(r)),
                write: Box::new(TlsRecordWriter::new(w)),
            })
        }
        None => {
            log_debug(&format!(
                "[{}] Fake TLS verify failed (size={} rec={}) -> masking",
                label,
                client_hello.len(),
                record_len
            ));
            proxy_to_masking_domain(conn, client_hello, masking, label).await;
            None
        }
    }
}

async fn proxy_to_masking_domain(conn: TcpStream, initial: Vec<u8>, domain: &str, label: &str) {
    let upstream = match tokio::time::timeout(
        MASKING_CONNECT_TIMEOUT,
        TcpStream::connect((domain, 443u16)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            log_warn(&format!(
                "[{}] masking: cannot connect to {}:443",
                label, domain
            ));
            return;
        }
    };

    log_debug(&format!("[{}] masking -> {}:443", label, domain));
    STATS
        .connections_masked
        .fetch_add(1, Ordering::Relaxed);

    let mut upstream = upstream;
    if upstream.write_all(&initial).await.is_err() {
        return;
    }

    let (mut c_read, mut c_write) = tokio::io::split(conn);
    let (mut u_read, mut u_write) = tokio::io::split(upstream);

    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut c_read, &mut u_write).await;
        let _ = u_write.shutdown().await;
    });
    let down = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut u_read, &mut c_write).await;
        let _ = c_write.shutdown().await;
    });

    let _ = tokio::join!(up, down);
}
