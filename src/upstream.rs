use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

static NEXT_ID: AtomicU16 = AtomicU16::new(1);

pub enum QueryResult {
    Answer(Message),
    Transport,
}

pub async fn query(
    server: SocketAddr,
    name: &Name,
    qtype: RecordType,
    recursion_desired: bool,
    limit: Duration,
) -> QueryResult {
    let bytes = match build_query(name, qtype, recursion_desired) {
        Ok(bytes) => bytes,
        Err(_) => return QueryResult::Transport,
    };
    match timeout(limit, query_udp(server, &bytes)).await {
        Ok(Ok(message)) if message.metadata.truncation => {
            match timeout(limit, query_tcp(server, &bytes)).await {
                Ok(Ok(message)) => QueryResult::Answer(message),
                _ => QueryResult::Answer(message),
            }
        }
        Ok(Ok(message)) => QueryResult::Answer(message),
        _ => match timeout(limit, query_tcp(server, &bytes)).await {
            Ok(Ok(message)) => QueryResult::Answer(message),
            _ => QueryResult::Transport,
        },
    }
}

pub(crate) fn build_query(
    name: &Name,
    qtype: RecordType,
    recursion_desired: bool,
) -> Result<Vec<u8>, ()> {
    let mut message = Message::new(
        NEXT_ID.fetch_add(1, Ordering::Relaxed),
        MessageType::Query,
        OpCode::Query,
    );
    message.metadata.recursion_desired = recursion_desired;
    message.add_query(Query::query(name.clone(), qtype));
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    message.set_edns(edns);
    message.to_bytes().map_err(|_| ())
}

async fn query_udp(server: SocketAddr, bytes: &[u8]) -> Result<Message, ()> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await.map_err(|_| ())?;
    socket.send_to(bytes, server).await.map_err(|_| ())?;
    let mut buf = vec![0u8; 4096];
    let (len, _) = socket.recv_from(&mut buf).await.map_err(|_| ())?;
    Message::from_bytes(&buf[..len]).map_err(|_| ())
}

async fn query_tcp(server: SocketAddr, bytes: &[u8]) -> Result<Message, ()> {
    let mut stream = TcpStream::connect(server).await.map_err(|_| ())?;
    let len = u16::try_from(bytes.len()).map_err(|_| ())?;
    stream.write_all(&len.to_be_bytes()).await.map_err(|_| ())?;
    stream.write_all(bytes).await.map_err(|_| ())?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.map_err(|_| ())?;
    let size = u16::from_be_bytes(len_buf) as usize;
    if size > 65_535 {
        return Err(());
    }
    let mut buf = vec![0u8; size];
    stream.read_exact(&mut buf).await.map_err(|_| ())?;
    Message::from_bytes(&buf).map_err(|_| ())
}
