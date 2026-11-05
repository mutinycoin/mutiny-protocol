//! Actual authenticated loopback frames and durable reassembly. The public TEST
//! owner registers exact transport pins; this does not qualify real admission.
use super::fixture::Fixture;
use mutinyd_v8::hybrid_peer_admission_v2::{PeerLink,Received,Registry};
use mutiny_transport_v2::{Endpoint,MAX_PAYLOAD,objects::{ObjectKind,ObjectQueue,Offer,MAX_BITMAP_BITS},object_link::Event};
use std::{net::{TcpListener,TcpStream},path::Path,time::{Duration,Instant}};
pub fn limit() -> Instant {Instant::now()+Duration::from_secs(5)}
pub struct Pair {pub send:PeerLink,pub recv:PeerLink,pub outgoing:Registry,pub incoming:Registry}
pub struct Completed {pub event:Received,pub offer:Offer,pub acknowledgments:Vec<Vec<u8>>}
impl Pair {
    pub fn open(f:&Fixture,root:&Path,initialize:bool) -> Self {
        Self::open_network(f,root,initialize,f.parent.genesis,f.parent.fingerprint)
    }
    /// Wrong-network software control still uses real hybrid socket identities;
    /// it must never pass the runtime's canonical-network gate.
    pub fn open_network(f:&Fixture,root:&Path,initialize:bool,genesis:[u8;32],fingerprint:[u8;32]) -> Self {
        let (a,b)=f.transport_keys();
        let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
        let outgoing=Registry::new(genesis,fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
        let incoming=Registry::new(genesis,fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
        let pending=incoming.begin().unwrap();let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();let socket=listener.accept().unwrap().0;drop(listener);
        let remote=pa.id();
        let server=std::thread::spawn(move||pending.respond(remote,socket,&b,Duration::from_secs(30)).unwrap());
        let client=outgoing.begin().unwrap().initiate(pb.id(),client,&a,Duration::from_secs(30)).unwrap();
        let server=server.join().unwrap();
        let tx=ObjectQueue::open_a2(&root.join("send-objects.sqlite"),client.peer_id(),initialize).unwrap();
        let rx=ObjectQueue::open_a2(&root.join("recv-objects.sqlite"),server.peer_id(),initialize).unwrap();
        Self {send:client.attach(tx).unwrap(),recv:server.attach(rx).unwrap(),outgoing,incoming}
    }
    pub fn deliver(&mut self,kind:ObjectKind,raw:&[u8]) -> Completed {
        let (offer,frame)=self.send.with_current(|l|l.enqueue(kind,raw,0)).unwrap().unwrap();
        self.deliver_advertised(offer,&frame)
    }
    /// Every fragment uses the actual authenticated socket/SQLite path. Receipt
    /// frames are only encoded here. The caller may publish them AFTER its exact
    /// full native durable handoff, never from opaque reassembly success alone.
    pub fn deliver_advertised(&mut self,offer:Offer,have:&[u8]) -> Completed {
        self.send.send(have,limit()).unwrap();let offered=self.recv.receive(limit()).unwrap();
        self.recv.dispatch_received(offered,|_,event|match event {Event::Offered(actual)=>assert_eq!(actual,offer),_=>panic!("expected actual HAVE")}).unwrap();
        let total=u16::try_from(offer.length.div_ceil(MAX_PAYLOAD)).unwrap();assert!(total>0);
        let mut start=0u16;let mut acknowledgments=Vec::new();
        while start<total {
            let request=self.recv.with_current(|l|l.next_missing_request(&offer.id,0,false)).unwrap().unwrap().unwrap();
            assert_eq!(request.start,start);assert_eq!(request.count,(total-start).min(MAX_BITMAP_BITS));
            self.recv.send(&request.frame,limit()).unwrap();let received=self.send.receive(limit()).unwrap();
            assert!(self.send.dispatch_received(received,|_,event|matches!(event,Event::Requested)).unwrap());
            for n in 0..request.count {
                let frame=self.send.with_current(|l|l.send_one()).unwrap().unwrap().unwrap();
                self.send.send(&frame,limit()).unwrap();let event=self.recv.receive(limit()).unwrap();
                let last=start+n+1==total;
                if last {
                    acknowledgments.push(self.recv.with_current(|l|l.receipt(&offer.id,start,request.count,0)).unwrap().unwrap());
                    let (actual,raw)=self.recv.with_current(|l|l.completed(&offer.id)).unwrap().unwrap();
                    assert_eq!(actual,offer);assert_eq!(raw.len(),offer.length);
                    return Completed {event,offer,acknowledgments};
                }
                assert!(self.recv.dispatch_received(event,|_,event|matches!(event,Event::FragmentReceived)).unwrap());
            }
            acknowledgments.push(self.recv.with_current(|l|l.receipt(&offer.id,start,request.count,0)).unwrap().unwrap());
            start=start.checked_add(request.count).unwrap();
        }
        panic!("full advertised object never completed")
    }
    pub fn publish_after_durable(&mut self,acknowledgments:Vec<Vec<u8>>) {
        for frame in acknowledgments {
            self.recv.send(&frame,limit()).unwrap();let received=self.send.receive(limit()).unwrap();
            assert!(self.send.dispatch_received(received,|_,event|matches!(event,Event::ReceiptRecorded)).unwrap());
        }
    }
    pub fn encode_all_receipts(&mut self,offer:&Offer) -> Vec<Vec<u8>> {
        let total=u16::try_from(offer.length.div_ceil(MAX_PAYLOAD)).unwrap();let mut start=0;let mut frames=Vec::new();
        while start<total {
            let count=(total-start).min(MAX_BITMAP_BITS);
            frames.push(self.recv.with_current(|l|l.receipt(&offer.id,start,count,0)).unwrap().unwrap());
            start=start.checked_add(count).unwrap();
        }
        frames
    }
}
