// EXTERNAL SOURCE-ONLY: nonshipping local TEST process control, never wallet approval/finality.
// OS process/channel authentication MUST precede decode_payload. The codec does not authenticate.
pub const MAGIC: [u8; 16] = *b"MW15LOCALCTRLV1\0";
pub const HEADER_BYTES: usize = 264;
pub const MAX_REQUEST_BYTES: usize = 1024;
pub const MAX_SUBMISSION_BYTES: u32 = 16384;
pub type Hash = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Bounds, Magic, Version, Role, Tag, Sequence, Context, Head, Payload, Order }
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { WalletA = 1, WalletC = 2, Treasury = 3 }
impl Role {
    fn decode(v: u8) -> Result<Self> {
        match v { 1 => Ok(Self::WalletA), 2 => Ok(Self::WalletC), 3 => Ok(Self::Treasury), _ => Err(Error::Role) }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag { Head = 1, Pump = 2, Certify = 3, Advertise = 4 }
impl Tag {
    fn decode(v: u8) -> Result<Self> {
        match v { 1 => Ok(Self::Head), 2 => Ok(Self::Pump), 3 => Ok(Self::Certify), 4 => Ok(Self::Advertise), _ => Err(Error::Tag) }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context { pub campaign: Hash, pub source: Hash, pub h0: Hash, pub genesis: Hash, pub fingerprint: Hash }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head { pub height: u64, pub block: Hash, pub root: Hash }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub tag: Tag, pub role: Role, pub sequence: u64, pub context: Context,
    pub expected_head: Head, pub payload_bytes: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Head,
    Pump { list: u8, kind: u8, id: Hash, wire_commitment: Hash, raw_bytes: u32 },
    Certify { next_epoch: bool, ids: Vec<Hash> },
    Advertise { height: u64, block: Hash },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request { pub header: Header, pub action: Action }

fn hash(bytes: &[u8]) -> Hash { bytes.try_into().expect("fixed bounded slice") }
fn nonzero(h: Hash) -> bool { h != [0; 32] }
fn valid_context(c: Context) -> bool {
    [c.campaign, c.source, c.h0, c.genesis, c.fingerprint].into_iter().all(nonzero)
}
// Exact header only; reject allocation size and cheap syntax BEFORE reading payload.
pub fn decode_header(bytes: &[u8]) -> Result<Header> {
    if bytes.len() != HEADER_BYTES { return Err(Error::Bounds); }
    if bytes[..16] != MAGIC { return Err(Error::Magic); }
    if u16::from_be_bytes(bytes[16..18].try_into().unwrap()) != 1 { return Err(Error::Version); }
    let tag = Tag::decode(bytes[18])?;
    let role = Role::decode(bytes[19])?;
    let sequence = u64::from_be_bytes(bytes[20..28].try_into().unwrap());
    if sequence == 0 { return Err(Error::Sequence); }
    let context = Context { campaign: hash(&bytes[28..60]), source: hash(&bytes[60..92]),
        h0: hash(&bytes[92..124]), genesis: hash(&bytes[124..156]), fingerprint: hash(&bytes[156..188]) };
    if !valid_context(context) { return Err(Error::Context); }
    let expected_head = Head { height: u64::from_be_bytes(bytes[188..196].try_into().unwrap()),
        block: hash(&bytes[196..228]), root: hash(&bytes[228..260]) };
    let payload_bytes = u32::from_be_bytes(bytes[260..264].try_into().unwrap());
    let n = payload_bytes as usize;
    if n > MAX_REQUEST_BYTES - HEADER_BYTES { return Err(Error::Bounds); }
    match tag {
        Tag::Head if n == 0 => {},
        Tag::Pump if n == 70 => {},
        Tag::Certify if (34..=514).contains(&n) && (n - 2) % 32 == 0 => {},
        Tag::Advertise if n == 40 => {},
        _ => return Err(Error::Payload),
    }
    Ok(Header { tag, role, sequence, context, expected_head, payload_bytes })
}
// Call ONLY after independently pinned live OS process/channel has authenticated.
// Pins and sequence come from server bootstrap/serialized own snapshot, never request fields.
pub fn check_pins(h: Header, role: Role, next_sequence: u64, context: Context, head: Head) -> Result<()> {
    if h.role != role { return Err(Error::Role); }
    if next_sequence == 0 || h.sequence != next_sequence { return Err(Error::Sequence); }
    if h.context != context || !valid_context(context) { return Err(Error::Context); }
    if h.expected_head != head { return Err(Error::Head); }
    Ok(())
}
pub fn decode_payload(header: Header, payload: &[u8]) -> Result<Request> {
    // Revalidate externally constructible Header; callers cannot skip size/tag constraints.
    if decode_header(&encode_header(header)?)? != header || payload.len() != header.payload_bytes as usize {
        return Err(Error::Bounds);
    }
    let action = match header.tag {
        Tag::Head => Action::Head,
        Tag::Pump => {
            let (list, kind) = (payload[0], payload[1]);
            // Production native decoder remains authority for list1 exact kind/body.
            if list > 1 || kind == 0 || (list == 0 && !matches!(kind, 1 | 2)) || (list == 1 && matches!(kind, 1 | 2 | 254)) {
                return Err(Error::Payload);
            }
            let id = hash(&payload[2..34]);
            let wire_commitment = hash(&payload[34..66]);
            let raw_bytes = u32::from_be_bytes(payload[66..70].try_into().unwrap());
            if !nonzero(id) || !nonzero(wire_commitment) || !(1..=MAX_SUBMISSION_BYTES).contains(&raw_bytes) {
                return Err(Error::Payload);
            }
            Action::Pump { list, kind, id, wire_commitment, raw_bytes }
        },
        Tag::Certify => {
            let mode = payload[0];
            let count = payload[1] as usize;
            if mode > 1 || !(1..=16).contains(&count) || payload.len() != 2 + 32 * count { return Err(Error::Payload); }
            let mut ids = Vec::with_capacity(count);
            for raw in payload[2..].chunks_exact(32) {
                let id = hash(raw);
                if !nonzero(id) || ids.last().is_some_and(|prior| prior >= &id) { return Err(Error::Order); }
                ids.push(id);
            }
            Action::Certify { next_epoch: mode == 1, ids }
        },
        Tag::Advertise => {
            let height = u64::from_be_bytes(payload[..8].try_into().unwrap());
            let block = hash(&payload[8..40]);
            if height == 0 || !nonzero(block) { return Err(Error::Payload); }
            Action::Advertise { height, block }
        },
    };
    Ok(Request { header, action })
}
pub fn encode_header(h: Header) -> Result<[u8; HEADER_BYTES]> {
    let mut b = [0; HEADER_BYTES];
    b[..16].copy_from_slice(&MAGIC); b[16..18].copy_from_slice(&1u16.to_be_bytes());
    b[18] = h.tag as u8; b[19] = h.role as u8; b[20..28].copy_from_slice(&h.sequence.to_be_bytes());
    for (offset, x) in [(28,h.context.campaign),(60,h.context.source),(92,h.context.h0),(124,h.context.genesis),(156,h.context.fingerprint)] {
        b[offset..offset+32].copy_from_slice(&x);
    }
    b[188..196].copy_from_slice(&h.expected_head.height.to_be_bytes());
    b[196..228].copy_from_slice(&h.expected_head.block); b[228..260].copy_from_slice(&h.expected_head.root);
    b[260..264].copy_from_slice(&h.payload_bytes.to_be_bytes());
    decode_header(&b)?; Ok(b)
}
pub fn encode(request: &Request) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(MAX_REQUEST_BYTES - HEADER_BYTES);
    match &request.action {
        Action::Head => {},
        Action::Pump { list, kind, id, wire_commitment, raw_bytes } => {
            payload.extend_from_slice(&[*list,*kind]); payload.extend_from_slice(id);
            payload.extend_from_slice(wire_commitment); payload.extend_from_slice(&raw_bytes.to_be_bytes());
        },
        Action::Certify { next_epoch, ids } => {
            if !(1..=16).contains(&ids.len()) { return Err(Error::Bounds); }
            payload.extend_from_slice(&[u8::from(*next_epoch),ids.len() as u8]);
            for id in ids { payload.extend_from_slice(id); }
        },
        Action::Advertise { height, block } => { payload.extend_from_slice(&height.to_be_bytes()); payload.extend_from_slice(block); },
    }
    let decoded = decode_payload(request.header, &payload)?;
    if decoded != *request { return Err(Error::Tag); }
    let mut bytes = encode_header(request.header)?.to_vec(); bytes.extend_from_slice(&payload); Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn header(tag: Tag, payload_bytes: u32) -> Header {
        Header { tag, role: Role::WalletA, sequence: 1,
            context: Context { campaign:[1;32],source:[2;32],h0:[3;32],genesis:[4;32],fingerprint:[5;32] },
            expected_head: Head { height:0,block:[6;32],root:[7;32] }, payload_bytes }
    }
    fn requests() -> [Request;4] {
        [Request {header:header(Tag::Head,0),action:Action::Head},
         Request {header:header(Tag::Pump,70),action:Action::Pump{list:0,kind:1,id:[8;32],wire_commitment:[9;32],raw_bytes:3508}},
         Request {header:header(Tag::Certify,66),action:Action::Certify{next_epoch:false,ids:vec![[8;32],[9;32]]}},
         Request {header:header(Tag::Advertise,40),action:Action::Advertise{height:1,block:[10;32]}}]
    }
    #[test] fn four_roundtrips_and_every_truncation_or_extension() {
        for r in requests() {
            let b=encode(&r).unwrap(); let h=decode_header(&b[..HEADER_BYTES]).unwrap();
            assert_eq!(decode_payload(h,&b[HEADER_BYTES..]).unwrap(),r);
            for n in 0..HEADER_BYTES { assert!(decode_header(&b[..n]).is_err()); }
            for n in HEADER_BYTES..b.len() { assert!(decode_payload(h,&b[HEADER_BYTES..n]).is_err()); }
            let mut extra=b[HEADER_BYTES..].to_vec(); extra.push(0); assert!(decode_payload(h,&extra).is_err());
        }
    }
    #[test] fn every_context_byte_and_stale_head_pin_refuses() {
        let h=header(Tag::Head,0); let b=encode_header(h).unwrap();
        check_pins(h,h.role,1,h.context,h.expected_head).unwrap();
        for n in 28..260 { let mut altered=b; altered[n]^=1; let changed=decode_header(&altered).unwrap(); assert!(check_pins(changed,h.role,1,h.context,h.expected_head).is_err()); }
        assert_eq!(check_pins(h,Role::Treasury,1,h.context,h.expected_head),Err(Error::Role));
        assert_eq!(check_pins(h,h.role,2,h.context,h.expected_head),Err(Error::Sequence));
    }
    #[test] fn reserved_header_and_oversize_refuse_before_payload() {
        let h=header(Tag::Head,0); let b=encode_header(h).unwrap();
        for n in 0..18 { let mut altered=b; altered[n]^=1; assert!(decode_header(&altered).is_err()); }
        for (offset,value) in [(18,0),(18,5),(19,0),(19,4)] { let mut altered=b; altered[offset]=value; assert!(decode_header(&altered).is_err()); }
        let mut altered=b; altered[20..28].fill(0); assert_eq!(decode_header(&altered),Err(Error::Sequence));
        altered=b; altered[260..264].copy_from_slice(&u32::MAX.to_be_bytes()); assert_eq!(decode_header(&altered),Err(Error::Bounds));
    }
    #[test] fn certify_order_and_mode_and_counts_refuse() {
        for ids in [vec![],vec![[8;32];17],vec![[8;32],[8;32]],vec![[9;32],[8;32]],vec![[0;32]]] {
            let r=Request{header:header(Tag::Certify,(2+32*ids.len()) as u32),action:Action::Certify{next_epoch:false,ids}};
            assert!(encode(&r).is_err());
        }
        let h=header(Tag::Certify,34); let mut p=vec![2,1];p.extend_from_slice(&[8;32]);assert!(decode_payload(h,&p).is_err());
    }
    #[test] fn pump_no_bytes_paths_or_zero_identity_and_limits() {
        let base=requests()[1].clone();
        let b=encode(&base).unwrap(); let h=base.header;
        for size in [0,16385,u32::MAX] { let mut p=b[HEADER_BYTES..].to_vec();p[66..70].copy_from_slice(&size.to_be_bytes());assert!(decode_payload(h,&p).is_err()); }
        for (list,kind) in [(2,1),(0,10),(1,1),(1,254),(1,0)] {let mut p=b[HEADER_BYTES..].to_vec();p[0]=list;p[1]=kind;assert!(decode_payload(h,&p).is_err());}
        for span in [2..34,34..66] { let mut p=b[HEADER_BYTES..].to_vec();p[span].fill(0);assert!(decode_payload(h,&p).is_err()); }
    }
}
