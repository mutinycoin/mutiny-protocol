//! Outbound pinned peer transport. The owner calls this outside the node actor.
//! Failed delivery is not proof of rejection; callers retry durable identities.
use crate::{
    deadline_io::DeadlineIo,
    peer::{MAX_FRAME, Session},
};
use ed25519_dalek::SigningKey;
use mutiny_consensus_v8::Hash;
use serde_json::{Value, json};
use std::{
    net::{SocketAddr, TcpStream},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const DEADLINE: Duration = Duration::from_secs(15);
pub struct PeerClient {
    stream: TcpStream,
    session: Session,
    request: u64,
    usable: bool,
}
impl PeerClient {
    pub(crate) fn interrupt_handle(&self) -> Result<TcpStream> {
        self.stream.try_clone().map_err(|e| e.to_string())
    }
    pub fn connect(
        address: SocketAddr,
        key: SigningKey,
        remote: Hash,
        genesis: Hash,
        fingerprint: Hash,
    ) -> Result<Self> {
        if remote == key.verifying_key().to_bytes() {
            return Err("Peer reflection".into());
        }
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        stream.set_nodelay(true).map_err(|e| e.to_string())?;
        let session = Session::handshake(
            &mut DeadlineIo::new(&mut stream, DEADLINE).map_err(|e| e.to_string())?,
            key,
            remote,
            genesis,
            fingerprint,
            true,
        )?;
        Ok(Self {
            stream,
            session,
            request: 0,
            usable: true,
        })
    }
    /// A single outstanding request owns the socket. No implicit replay occurs.
    /// Protocol errors poison this connection; application rejection does not.
    pub fn request(
        &mut self,
        method: &str,
        arguments: &serde_json::Map<String, Value>,
    ) -> Result<Value> {
        if !self.usable || self.request >= 4096 {
            return Err("Peer client unavailable/request bound".into());
        }
        if arguments.contains_key("id") || arguments.contains_key("method") {
            return Err("Reserved request field".into());
        }
        let mut message = arguments.clone();
        message.insert("id".into(), json!(self.request));
        message.insert("method".into(), json!(method));
        let raw = serde_json::to_vec(&message).map_err(|e| e.to_string())?;
        if raw.len() > MAX_FRAME - 128 {
            return Err("Peer request bound".into());
        }
        self.usable = false;
        self.session.send(
            &mut DeadlineIo::new(&mut self.stream, DEADLINE).map_err(|e| e.to_string())?,
            &raw,
        )?;
        let raw = self.session.receive(
            &mut DeadlineIo::new(&mut self.stream, DEADLINE).map_err(|e| e.to_string())?,
        )?;
        let answer: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if !answer.is_object()
            || answer["id"].as_u64() != Some(self.request)
            || (answer.get("result").is_some() == answer.get("error").is_some())
        {
            return Err("Peer response correlation/schema".into());
        }
        self.request += 1;
        self.usable = method != "end_session";
        if let Some(error) = answer.get("error") {
            return Err(format!("Peer rejected: {error}"));
        }
        Ok(answer["result"].clone())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_server::{PeerBackend, PeerReply, PeerServer};
    use std::{
        net::TcpListener,
        sync::{Arc, Mutex},
    };
    struct Backend;
    impl PeerBackend for Backend {
        fn context(&self) -> (Hash, Hash) {
            ([1; 32], [2; 32])
        }
        fn handle(&mut self, _: Hash, raw: &[u8]) -> Result<PeerReply> {
            let req: Value = serde_json::from_slice(raw).unwrap();
            let response = match req["method"].as_str().unwrap() {
                "reject" => json!({"id":req["id"],"error":"not accepted"}),
                "bad_id" => json!({"id":999,"result":{}}),
                _ => json!({"id":req["id"],"result":{"ok":true}}),
            };
            Ok(PeerReply {
                payload: serde_json::to_vec(&response).unwrap(),
                close: req["method"] == "end_session",
            })
        }
    }
    #[test]
    fn bounded_client_pins_context_correlates_response_and_poisoned_transport() {
        let a = SigningKey::from_bytes(&[31; 32]);
        let b = SigningKey::from_bytes(&[32; 32]);
        let bp = b.verifying_key().to_bytes();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = PeerServer::start(
            listener,
            b,
            &[a.verifying_key().to_bytes()],
            Arc::new(Mutex::new(Backend)),
            4,
        )
        .unwrap();
        assert!(PeerClient::connect(address, a.clone(), bp, [3; 32], [2; 32]).is_err());
        let mut client = PeerClient::connect(address, a.clone(), bp, [1; 32], [2; 32]).unwrap();
        let args = serde_json::Map::new();
        assert!(client.request("reject", &args).is_err());
        assert_eq!(client.request("status", &args).unwrap(), json!({"ok":true}));
        let mut reserved = args.clone();
        reserved.insert("id".into(), json!(0));
        assert!(client.request("status", &reserved).is_err());
        assert!(client.request("bad_id", &args).is_err());
        assert!(client.request("status", &args).is_err());
        drop(client);
        server.stop().unwrap();
    }
}
