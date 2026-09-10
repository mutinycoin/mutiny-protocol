use super::*;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

pub const DEFAULT_RPC_LISTEN: &str = "127.0.0.1:24589";
pub const RPC_TOKEN_FILE_LEN: usize = 40;
const RPC_TOKEN_MAGIC: &[u8; 8] = b"MUTRPCT1";
const RPC_TOKEN_LEN: usize = 32;
const RPC_MAX_LINE_BYTES: usize = 65_536;
const RPC_IO_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
const RPC_MAX_CONCURRENT_WORKERS: usize = 16;
const RPC_PROTOCOL: &str = "2.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcWireRequest {
    jsonrpc: String,
    id: u64,
    token: String,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcWireError {
    code: i64,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcWireResponse {
    jsonrpc: String,
    id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcWireError>,
}

impl RpcWireResponse {
    fn ok(id: u64, result: Value) -> Self {
        Self {
            jsonrpc: RPC_PROTOCOL.into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: u64, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: RPC_PROTOCOL.into(),
            id,
            result: None,
            error: Some(RpcWireError {
                code,
                message: message.into(),
            }),
        }
    }
}

pub fn create_token_file(path: &Path) -> Result<(), String> {
    let mut token = [0u8; RPC_TOKEN_LEN];
    OsRng.fill_bytes(&mut token);
    let bytes = encode_token_file(&token);
    mutiny_keystore::write_new_file(path, &bytes).map_err(|e| e.to_string())?;
    token.fill(0);
    Ok(())
}

fn encode_token_file(token: &[u8; RPC_TOKEN_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RPC_TOKEN_FILE_LEN);
    out.extend_from_slice(RPC_TOKEN_MAGIC);
    out.extend_from_slice(token);
    out
}

fn decode_token_file(bytes: &[u8]) -> Result<[u8; RPC_TOKEN_LEN], String> {
    if bytes.len() != RPC_TOKEN_FILE_LEN {
        return Err(format!(
            "MutinyRpcTokenV1 must be exactly {RPC_TOKEN_FILE_LEN} bytes"
        ));
    }
    if &bytes[..8] != RPC_TOKEN_MAGIC {
        return Err("MutinyRpcTokenV1 magic mismatch".into());
    }
    Ok(bytes[8..].try_into().unwrap())
}

fn load_token(path: &Path) -> Result<[u8; RPC_TOKEN_LEN], String> {
    let bytes = fs::read(path).map_err(|e| format!("read RPC token {}: {e}", path.display()))?;
    decode_token_file(&bytes)
}

fn constant_time_eq(a: &[u8; RPC_TOKEN_LEN], b: &[u8; RPC_TOKEN_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..RPC_TOKEN_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn parse_wire_token(value: &str) -> Result<[u8; RPC_TOKEN_LEN], String> {
    if value.len() != RPC_TOKEN_LEN * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("RPC bearer token must be exactly 64 hexadecimal characters".into());
    }
    let bytes = hex::decode(value).map_err(|_| "invalid RPC bearer token hex")?;
    Ok(bytes.try_into().unwrap())
}

fn validate_loopback_addr(value: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = value
        .parse()
        .map_err(|_| "RPC endpoint must be an IP socket address such as 127.0.0.1:24589")?;
    if !addr.ip().is_loopback() {
        return Err(
            "Build 5.9 RPC is loopback-only; non-loopback bind/connect addresses are refused"
                .into(),
        );
    }
    Ok(addr)
}

fn forbidden_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    [
        "passphrase",
        "password",
        "secret",
        "seed",
        "private_key",
        "private-key",
        "mnemonic",
    ]
    .iter()
    .any(|needle| k.contains(needle))
}

fn reject_secret_params(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if forbidden_secret_key(key) {
                    return Err(format!("RPC parameter key '{key}' is forbidden; wallet secret material is not accepted by Build 5.9 RPC"));
                }
                reject_secret_params(child)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                reject_secret_params(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn read_line_bounded(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while out.len() <= RPC_MAX_LINE_BYTES {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(1) => {
                if byte[0] == b'\n' {
                    return Ok(out);
                }
                if byte[0] != b'\r' {
                    out.push(byte[0]);
                }
            }
            Ok(_) => unreachable!(),
            Err(e) => return Err(format!("RPC read failed: {e}")),
        }
    }
    if out.len() > RPC_MAX_LINE_BYTES {
        return Err(format!("RPC request exceeds {RPC_MAX_LINE_BYTES} bytes"));
    }
    if out.is_empty() {
        return Err("empty RPC request".into());
    }
    Ok(out)
}

fn write_response(stream: &mut TcpStream, response: &RpcWireResponse) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(response).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .map_err(|e| format!("RPC write failed: {e}"))?;
    stream.flush().map_err(|e| format!("RPC flush failed: {e}"))
}

pub fn serve(
    data_dir: &Path,
    listen: &str,
    token_path: &Path,
    max_requests: Option<u64>,
) -> Result<(), String> {
    let addr = validate_loopback_addr(listen)?;
    let token = load_token(token_path)?;
    let listener = TcpListener::bind(addr).map_err(|e| format!("bind RPC {addr}: {e}"))?;
    println!("Build 5.9 authenticated RPC listening on {addr}");
    println!("Transport: newline-delimited JSON-RPC 2.0, one request per connection");
    println!("Methods: system.version, chain.status, wallet.balances, wallet.utxos, licenses.list, mempool.list, offline.submit");
    println!("Wallet passphrases, seeds and private keys are forbidden RPC parameters.");
    serve_listener(listener, data_dir, token, max_requests)
}

fn serve_connection(
    mut stream: TcpStream,
    data_dir: PathBuf,
    mut token: [u8; RPC_TOKEN_LEN],
) -> Result<(), String> {
    let result = (|| {
        let peer = stream
            .peer_addr()
            .map_err(|e| format!("RPC peer address: {e}"))?;
        if !peer.ip().is_loopback() {
            return Ok(());
        }
        stream
            .set_read_timeout(Some(RPC_IO_TIMEOUT))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(RPC_IO_TIMEOUT))
            .map_err(|e| e.to_string())?;
        let response = match read_line_bounded(&mut stream) {
            Ok(line) => handle_line(&data_dir, &token, &line),
            Err(e) => RpcWireResponse::err(0, -32700, e),
        };
        let _ = write_response(&mut stream, &response);
        Ok(())
    })();
    token.fill(0);
    result
}

fn reap_rpc_workers(workers: &mut Vec<thread::JoinHandle<()>>) {
    let mut live = Vec::with_capacity(workers.len());
    for worker in workers.drain(..) {
        if worker.is_finished() {
            let _ = worker.join();
        } else {
            live.push(worker);
        }
    }
    *workers = live;
}

fn serve_listener(
    listener: TcpListener,
    data_dir: &Path,
    mut token: [u8; RPC_TOKEN_LEN],
    max_requests: Option<u64>,
) -> Result<(), String> {
    let mut handled = 0u64;
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    for incoming in listener.incoming() {
        reap_rpc_workers(&mut workers);
        let stream = incoming.map_err(|e| format!("accept RPC connection: {e}"))?;
        let peer = stream
            .peer_addr()
            .map_err(|e| format!("RPC peer address: {e}"))?;
        if !peer.ip().is_loopback() {
            continue;
        }

        handled = handled.saturating_add(1);
        if workers.len() >= RPC_MAX_CONCURRENT_WORKERS {
            drop(stream);
        } else {
            let worker_dir = data_dir.to_path_buf();
            let worker_token = token;
            workers.push(thread::spawn(move || {
                if let Err(e) = serve_connection(stream, worker_dir, worker_token) {
                    eprintln!("RPC worker failed: {e}");
                }
            }));
        }

        if max_requests.is_some_and(|limit| handled >= limit) {
            break;
        }
    }

    for worker in workers {
        let _ = worker.join();
    }
    token.fill(0);
    Ok(())
}

pub fn call(
    server: &str,
    token_path: &Path,
    method: &str,
    params_json: &str,
) -> Result<Value, String> {
    let addr = validate_loopback_addr(server)?;
    if method.is_empty()
        || method.len() > 64
        || !method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
    {
        return Err("RPC method must be 1..64 ASCII alphanumeric/dot/underscore characters".into());
    }
    let token = load_token(token_path)?;
    let params: Value = serde_json::from_str(params_json)
        .map_err(|e| format!("--params-json is invalid JSON: {e}"))?;
    reject_secret_params(&params)?;
    let request = RpcWireRequest {
        jsonrpc: RPC_PROTOCOL.into(),
        id: 1,
        token: hex::encode(token),
        method: method.into(),
        params,
    };
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect RPC {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(RPC_RESPONSE_TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(RPC_IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let mut bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .map_err(|e| format!("RPC write failed: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("RPC flush failed: {e}"))?;
    let line = read_line_bounded(&mut stream)?;
    let response: RpcWireResponse =
        serde_json::from_slice(&line).map_err(|e| format!("decode RPC response: {e}"))?;
    if response.jsonrpc != RPC_PROTOCOL || response.id != 1 {
        return Err("RPC response protocol/id mismatch".into());
    }
    if let Some(error) = response.error {
        return Err(format!("RPC {}: {}", error.code, error.message));
    }
    response
        .result
        .ok_or_else(|| "RPC response contained neither result nor error".into())
}

fn handle_line(
    data_dir: &Path,
    expected_token: &[u8; RPC_TOKEN_LEN],
    line: &[u8],
) -> RpcWireResponse {
    let parsed: RpcWireRequest = match serde_json::from_slice(line) {
        Ok(v) => v,
        Err(e) => return RpcWireResponse::err(0, -32700, format!("invalid JSON-RPC request: {e}")),
    };
    if parsed.jsonrpc != RPC_PROTOCOL {
        return RpcWireResponse::err(parsed.id, -32600, "jsonrpc must be exactly '2.0'");
    }
    if parsed.method.is_empty() || parsed.method.len() > 64 {
        return RpcWireResponse::err(parsed.id, -32600, "invalid RPC method length");
    }
    let supplied = match parse_wire_token(&parsed.token) {
        Ok(v) => v,
        Err(e) => return RpcWireResponse::err(parsed.id, -32001, e),
    };
    if !constant_time_eq(expected_token, &supplied) {
        return RpcWireResponse::err(parsed.id, -32001, "RPC authentication failed");
    }
    if let Err(e) = reject_secret_params(&parsed.params) {
        return RpcWireResponse::err(parsed.id, -32602, e);
    }
    match dispatch(data_dir, &parsed.method, &parsed.params) {
        Ok(result) => RpcWireResponse::ok(parsed.id, result),
        Err(e) => RpcWireResponse::err(parsed.id, -32000, e),
    }
}

fn dispatch(data_dir: &Path, method: &str, params: &Value) -> Result<Value, String> {
    match method {
        "system.version" => {
            require_empty_params(params)?;
            let state = load_state(data_dir)?;
            Ok(json!({
                "build": BUILD_NAME,
                "motto": MOTTO,
                "network_id": format!("0x{DEVNET_NETWORK_ID:08x}"),
                "genesis_id": state.genesis_hash.clone(),
                "rpc_transport": "json-rpc-2.0-jsonl",
                "loopback_only": true,
            }))
        }
        "chain.status" => {
            require_empty_params(params)?;
            let state = load_state(data_dir)?;
            let canonical_state_root = state
                .blocks
                .last()
                .map(|b| b.state_root.clone())
                .unwrap_or_else(|| state.current_state_root.clone());
            let next_epoch = next_mineable_epoch(&state);
            Ok(json!({
                "height": state.height,
                "tip_epoch": state.tip_epoch,
                "next_mineable_epoch": next_epoch,
                "eligible_licenses": eligible_license_count(&state, next_epoch),
                "licenses_total": state.licenses.len(),
                "tip": state.tip_hash.clone(),
                "canonical_state_root": canonical_state_root,
                "current_state_root": state.current_state_root.clone(),
                "chainwork": chainwork_hex(&state)?,
                "mempool_count": state.mempool.len(),
                "pending_protocol_operations": state.pending_protocol_operations.len(),
            }))
        }
        "wallet.balances" => {
            let state = load_state(data_dir)?;
            rpc_balances(&state, params)
        }
        "wallet.utxos" => {
            let state = load_state(data_dir)?;
            rpc_utxos(&state, params)
        }
        "licenses.list" => {
            let state = load_state(data_dir)?;
            rpc_licenses(&state, params)
        }
        "mempool.list" => {
            let state = load_state(data_dir)?;
            rpc_mempool(&state, params)
        }
        "offline.submit" => rpc_offline_submit(data_dir, params),
        _ => Err(format!("RPC method not found: {method}")),
    }
}

fn require_empty_params(params: &Value) -> Result<(), String> {
    match params {
        Value::Null => Ok(()),
        Value::Object(map) if map.is_empty() => Ok(()),
        _ => Err("this RPC method takes no parameters".into()),
    }
}

fn rpc_balances(state: &DevnetState, params: &Value) -> Result<Value, String> {
    let (offset, limit) = parse_page_params(params, 64, &[])?;
    let candidate_height = state.height + 1;
    let reserved = mempool_reserved_inputs(state);
    let mut rows = Vec::with_capacity(state.licenses.len());
    for l in &state.licenses {
        let address = decode32(&l.payment_address_id)?;
        let mut total = 0u64;
        let mut spendable = 0u64;
        let mut immature = 0u64;
        let mut reserved_amount = 0u64;
        for u in &state.utxos {
            if u.output_type != OUTPUT_PUBKEY_HASH || decode32(&u.payload)? != address {
                continue;
            }
            total = total
                .checked_add(u.amount_strikes)
                .ok_or("balance overflow")?;
            if reserved.contains(&(u.txid.clone(), u.output_index)) {
                reserved_amount = reserved_amount
                    .checked_add(u.amount_strikes)
                    .ok_or("balance overflow")?;
            } else if u.spendable_at_height(candidate_height) {
                spendable = spendable
                    .checked_add(u.amount_strikes)
                    .ok_or("balance overflow")?;
            } else {
                immature = immature
                    .checked_add(u.amount_strikes)
                    .ok_or("balance overflow")?;
            }
        }
        rows.push(json!({
            "license": l.index + 1,
            "license_id": l.license_id.clone(),
            "total_strikes": total,
            "spendable_strikes": spendable,
            "immature_strikes": immature,
            "reserved_strikes": reserved_amount,
        }));
    }
    let treasury_total = dividends::treasury_total(&state.utxos)?;
    let treasury = dividends::treasury_state(state, &state.utxos)?;
    let total = rows.len();
    let page = rows
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    Ok(json!({
        "items": page,
        "offset": offset,
        "limit": limit,
        "total": total,
        "treasury_total_strikes": treasury_total,
        "treasury_available_strikes": treasury.available_strikes,
        "treasury_reserved_strikes": treasury.reserved_dividend_strikes,
        "issued_strikes": state.total_issued_strikes,
    }))
}

fn rpc_utxos(state: &DevnetState, params: &Value) -> Result<Value, String> {
    let (offset, limit) = parse_page_params(params, 128, &["license"])?;
    let map = params
        .as_object()
        .ok_or("wallet.utxos params must be an object")?;
    let license = match map.get("license") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or("wallet.utxos license must be an integer")?;
            if n == 0 || n > state.licenses.len() as u64 {
                return Err("wallet.utxos license number out of range".into());
            }
            Some((n - 1) as usize)
        }
    };
    let filter_address = license
        .map(|i| decode32(&state.licenses[i].payment_address_id))
        .transpose()?;
    let candidate_height = state.height + 1;
    let mut rows = Vec::new();
    for u in &state.utxos {
        if let Some(addr) = filter_address {
            if u.output_type != OUTPUT_PUBKEY_HASH || decode32(&u.payload)? != addr {
                continue;
            }
        }
        rows.push(json!({
            "txid": u.txid.clone(),
            "output_index": u.output_index,
            "amount_strikes": u.amount_strikes,
            "output_type": u.output_type,
            "creation_height": u.creation_height,
            "creation_epoch": u.creation_epoch,
            "coinbase": u.coinbase,
            "spendable_next_height": u.spendable_at_height(candidate_height),
        }));
    }
    let total = rows.len();
    let page = rows
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    Ok(json!({"items": page, "offset": offset, "limit": limit, "total": total}))
}

fn rpc_licenses(state: &DevnetState, params: &Value) -> Result<Value, String> {
    let (offset, limit) = parse_page_params(params, 64, &[])?;
    let total = state.licenses.len();
    let items = state
        .licenses
        .iter()
        .skip(offset)
        .take(limit)
        .map(|l| {
            json!({
                "number": l.index + 1,
                "license_id": l.license_id.clone(),
                "status": l.status,
                "purchase_method": l.purchase_method,
                "owner_public_key": l.owner_public_key.clone(),
                "mining_public_key": l.mining_public_key.clone(),
                "owner_key_sequence": l.owner_key_sequence,
                "mining_key_sequence": l.mining_key_sequence,
                "activation_epoch": l.activation_epoch,
                "strikes": l.strike_weight,
                "suspended_until_epoch": l.suspended_until_epoch,
                "revocation_epoch": l.revocation_epoch,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({"items": items, "offset": offset, "limit": limit, "total": total}))
}

fn rpc_mempool(state: &DevnetState, params: &Value) -> Result<Value, String> {
    let (offset, limit) = parse_page_params(params, 128, &[])?;
    let total = state.mempool.len();
    let transactions = state
        .mempool
        .iter()
        .skip(offset)
        .take(limit)
        .map(|tx| {
            json!({
                "txid": tx.txid.clone(),
                "wtxid": tx.wtxid.clone(),
                "from_license": tx.from_license + 1,
                "to_license": tx.to_license + 1,
                "amount_strikes": tx.amount_strikes,
                "fee_strikes": tx.fee_strikes,
                "base_fee_strikes": tx.base_fee_strikes,
                "inputs": tx.inputs.len(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "items": transactions,
        "offset": offset,
        "limit": limit,
        "total": total,
        "pending_protocol_operations": state.pending_protocol_operations.len(),
    }))
}

fn parse_page_params(
    params: &Value,
    max_limit: usize,
    extra_keys: &[&str],
) -> Result<(usize, usize), String> {
    let map = params
        .as_object()
        .ok_or("paged RPC params must be an object")?;
    for key in map.keys() {
        if key != "offset"
            && key != "limit"
            && !extra_keys.iter().any(|allowed| key.as_str() == *allowed)
        {
            return Err(format!("unexpected RPC parameter '{key}'"));
        }
    }
    let offset_u64 = map
        .get("offset")
        .map(|v| v.as_u64().ok_or("offset must be a non-negative integer"))
        .transpose()?
        .unwrap_or(0);
    let limit_u64 = map
        .get("limit")
        .map(|v| v.as_u64().ok_or("limit must be a positive integer"))
        .transpose()?
        .unwrap_or(max_limit as u64);
    if limit_u64 == 0 || limit_u64 > max_limit as u64 {
        return Err(format!("limit must be in 1..={max_limit}"));
    }
    let offset = usize::try_from(offset_u64).map_err(|_| "offset is too large")?;
    let limit = usize::try_from(limit_u64).map_err(|_| "limit is too large")?;
    Ok((offset, limit))
}

fn rpc_offline_submit(data_dir: &Path, params: &Value) -> Result<Value, String> {
    let map = params
        .as_object()
        .ok_or("offline.submit params must be an object")?;
    if map.len() != 2 || !map.contains_key("request_hex") || !map.contains_key("signed_hex") {
        return Err("offline.submit requires exactly request_hex and signed_hex".into());
    }
    let request_hex = map
        .get("request_hex")
        .and_then(Value::as_str)
        .ok_or("request_hex must be a string")?;
    let signed_hex = map
        .get("signed_hex")
        .and_then(Value::as_str)
        .ok_or("signed_hex must be a string")?;
    if request_hex.len() > 16_384 || signed_hex.len() > 16_384 {
        return Err("offline.submit artifact hex exceeds Build 5.9 RPC bounds".into());
    }
    let request_bytes = hex::decode(request_hex).map_err(|_| "request_hex is invalid hex")?;
    let signed_bytes = hex::decode(signed_hex).map_err(|_| "signed_hex is invalid hex")?;
    let request = OfflineSpendRequestV1::decode(&request_bytes)?;
    let signed = OfflineSpendSignatureV1::decode(&signed_bytes)?;
    let mut state = load_state(data_dir)?;
    let pending = submit_offline_spend(&state, &request_bytes, &request, &signed)?;
    validate_pending_candidate(&state, &pending, false)?;
    let result = json!({
        "txid": pending.txid,
        "wtxid": pending.wtxid,
        "amount_strikes": pending.amount_strikes,
        "fee_strikes": pending.fee_strikes,
        "base_fee_strikes": pending.base_fee_strikes,
        "status": "MEMPOOL",
        "online_wallet_secret_loaded": false,
    });
    state.mempool.push(pending);
    save_state(data_dir, &state)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build59_rpc_token_file_is_exact_and_tamper_is_rejected() {
        let token: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let bytes = encode_token_file(&token);
        assert_eq!(bytes.len(), RPC_TOKEN_FILE_LEN);
        assert_eq!(&bytes[..8], b"MUTRPCT1");
        assert_eq!(decode_token_file(&bytes).unwrap(), token);
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "ba390d387b3ac8d2607f18ad43bcce32bc827c074bea258611ae60c3997fb556"
        );
        let wire = RpcWireRequest {
            jsonrpc: "2.0".into(),
            id: 7,
            token: hex::encode(token),
            method: "chain.status".into(),
            params: json!({}),
        };
        let mut wire_bytes = serde_json::to_vec(&wire).unwrap();
        wire_bytes.push(b'\n');
        assert_eq!(wire_bytes.len(), 136);
        assert_eq!(
            hex::encode(Sha256::digest(&wire_bytes)),
            "489cf341b56858e2cf85c7ab299158ef9d43978640cb940bd5f0b7797cb68690"
        );
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert!(decode_token_file(&bad).unwrap_err().contains("magic"));
    }

    #[test]
    fn build59_rpc_is_loopback_only_and_rejects_secret_params() {
        assert!(validate_loopback_addr("127.0.0.1:24589").is_ok());
        assert!(validate_loopback_addr("[::1]:24589").is_ok());
        assert!(validate_loopback_addr("0.0.0.0:24589")
            .unwrap_err()
            .contains("loopback-only"));
        assert!(validate_loopback_addr("192.0.2.10:24589")
            .unwrap_err()
            .contains("loopback-only"));
        assert!(reject_secret_params(&json!({"wallet_passphrase":"x"})).is_err());
        assert!(reject_secret_params(&json!({"nested":{"seed":"x"}})).is_err());
        assert!(reject_secret_params(&json!({"request_hex":"aa","signed_hex":"bb"})).is_ok());
        assert_eq!(parse_page_params(&json!({}), 64, &[]).unwrap(), (0, 64));
        assert_eq!(
            parse_page_params(&json!({"offset":2,"limit":3}), 64, &[]).unwrap(),
            (2, 3)
        );
        assert!(parse_page_params(&json!({"limit":65}), 64, &[]).is_err());
        assert!(parse_page_params(&json!({"unexpected":1}), 64, &[]).is_err());
    }

    #[test]
    fn build59_rpc_authentication_is_required_before_dispatch() {
        let token = [0x42u8; 32];
        let req = RpcWireRequest {
            jsonrpc: "2.0".into(),
            id: 7,
            token: hex::encode([0x43u8; 32]),
            method: "chain.status".into(),
            params: json!({}),
        };
        let line = serde_json::to_vec(&req).unwrap();
        let dir = PathBuf::from("does-not-matter-auth-fails-first");
        let response = handle_line(&dir, &token, &line);
        assert_eq!(response.id, 7);
        assert_eq!(response.error.unwrap().code, -32001);
    }

    #[test]
    fn build62_hotfix1_hotfix4_rpc_worker_concurrency_prevents_head_of_line_blocking() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build62-h4-rpc-concurrency-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let token_path = dir.join("rpc.token");
        let token = [0x66u8; 32];
        mutiny_keystore::write_new_file(&token_path, &encode_token_file(&token)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let dir2 = dir.clone();
        let server =
            thread::spawn(move || serve_listener(listener, &dir2, token, Some(2)).unwrap());

        let mut stalled = TcpStream::connect(addr).unwrap();
        stalled.write_all(b"{").unwrap();
        stalled.flush().unwrap();
        thread::sleep(Duration::from_millis(50));

        let started = Instant::now();
        let result = call(&addr.to_string(), &token_path, "chain.status", "{}").unwrap();
        let elapsed = started.elapsed();
        assert_eq!(result["height"], 0);
        assert!(
            elapsed < Duration::from_secs(2),
            "second authenticated RPC request was head-of-line blocked for {elapsed:?}"
        );

        drop(stalled);
        server.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build62_hotfix1_hotfix4_rpc_preserves_server_slow_client_bound_and_extends_client_response_horizon(
    ) {
        assert_eq!(RPC_IO_TIMEOUT, Duration::from_secs(5));
        assert_eq!(RPC_RESPONSE_TIMEOUT, Duration::from_secs(20));
        assert_eq!(RPC_MAX_CONCURRENT_WORKERS, 16);
    }

    #[test]
    fn build59_rpc_live_loopback_roundtrip_serves_status() {
        let dir = std::env::temp_dir().join(format!(
            "mutiny-build59-rpc-roundtrip-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        init_devnet(&dir, 1, true).unwrap();
        let token_path = dir.join("rpc.token");
        let token = [0x55u8; 32];
        mutiny_keystore::write_new_file(&token_path, &encode_token_file(&token)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let dir2 = dir.clone();
        let server =
            thread::spawn(move || serve_listener(listener, &dir2, token, Some(1)).unwrap());
        let result = call(&addr.to_string(), &token_path, "chain.status", "{}").unwrap();
        assert_eq!(result["height"], 0);
        assert_eq!(result["licenses_total"], 12);
        server.join().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
