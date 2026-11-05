//! Bounded encrypted enrollment-channel IO. Caller supplies an already completed
//! pinned hybrid Session and actual TCP connection; no peer self-supplied key,
//! TLS bypass, localhost assumption or execution-locality claim is introduced.
//! Run on a retained private worker, never block the UI/voter actor.
use super::{channel::PrivateChannel,exchange::{ChallengeFrame,ResponseFrame,MAX_FRAME},Error,Result};
use std::{io::{Read,Write},net::TcpStream,time::{Duration,Instant}};
use mutiny_transport_v2::MAX_PAYLOAD;
pub struct PrivateSocket {io:TcpStream,channel:PrivateChannel,deadline:Instant,poisoned:bool}
impl PrivateSocket {
    pub fn matches_network(&self,genesis:mutiny_consensus_v8::Hash,fingerprint:mutiny_consensus_v8::Hash)->bool{
        self.channel.matches_network(genesis,fingerprint)
    }
    /// This caller-chosen finite LOCAL IO deadline is not a consensus expiry or
    /// signing grant. The native gate independently checks trusted elapsed time.
    pub fn new(io:TcpStream,channel:PrivateChannel,lifetime:Duration)->Result<Self>{
        if lifetime.is_zero(){return Err(Error::Expired);}
        let deadline=Instant::now().checked_add(lifetime).ok_or(Error::Expired)?;
        Ok(Self{io,channel,deadline,poisoned:false})
    }
    fn remaining(&self)->Result<Duration>{
        if self.poisoned{return Err(Error::Endpoint);}
        let remaining=self.deadline.checked_duration_since(Instant::now()).ok_or(Error::Expired)?;
        if remaining.is_zero(){return Err(Error::Expired);}Ok(remaining)
    }
    fn write(&mut self,bytes:&[u8])->Result<()> {
        let mut at=0;
        while at<bytes.len(){
            self.io.set_write_timeout(Some(self.remaining()?)).map_err(|_|Error::Endpoint)?;
            match self.io.write(&bytes[at..]){
                Ok(0)=>return Err(Error::Endpoint),Ok(n)=>at+=n,
                Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>{},
                Err(_)=>return Err(Error::Endpoint),
            }
        }self.remaining()?;Ok(())
    }
    fn read(&mut self,bytes:&mut [u8])->Result<()> {
        let mut at=0;
        while at<bytes.len(){
            self.io.set_read_timeout(Some(self.remaining()?)).map_err(|_|Error::Endpoint)?;
            match self.io.read(&mut bytes[at..]){
                Ok(0)=>return Err(Error::Endpoint),Ok(n)=>at+=n,
                Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>{},
                Err(_)=>return Err(Error::Endpoint),
            }
        }self.remaining()?;Ok(())
    }
    fn send(&mut self,frames:Vec<Vec<u8>>)->Result<()> {
        if frames.is_empty()||frames.len()>MAX_FRAME.div_ceil(MAX_PAYLOAD){return Err(Error::Bounds);}
        self.write(&(frames.len() as u16).to_be_bytes())?;
        for frame in frames {
            if !(116..=255).contains(&frame.len()){return Err(Error::Bounds);}
            self.write(&(frame.len() as u16).to_be_bytes())?;self.write(&frame)?;
        }Ok(())
    }
    fn receive(&mut self,limit:usize)->Result<Vec<Vec<u8>>>{
        let mut size=[0;2];self.read(&mut size)?;let count=u16::from_be_bytes(size) as usize;
        if count==0||count>limit.div_ceil(MAX_PAYLOAD){return Err(Error::Bounds);}
        let mut frames=Vec::with_capacity(count);
        for _ in 0..count {
            self.read(&mut size)?;let n=u16::from_be_bytes(size) as usize;
            if !(116..=255).contains(&n){return Err(Error::Bounds);}
            let mut frame=vec![0;n];self.read(&mut frame)?;frames.push(frame);
        }Ok(frames)
    }
    fn finish<T>(&mut self,result:Result<T>)->Result<T>{
        if result.is_err(){self.poisoned=true;let _=self.io.shutdown(std::net::Shutdown::Both);}result
    }
    pub fn send_challenge(&mut self,expected:&ChallengeFrame)->Result<()> {
        let result=(||{self.remaining()?;let frames=self.channel.seal_challenge(expected)?;self.send(frames)})();self.finish(result)
    }
    pub fn receive_challenge(&mut self,expected:&ChallengeFrame)->Result<ChallengeFrame>{
        let result=(||{let frames=self.receive(MAX_FRAME)?;self.channel.open_challenge(expected,&frames)})();self.finish(result)
    }
    /// Receive against the endpoint's independently current native request.
    pub fn receive_requested_challenge(&mut self,request:&mutiny_consensus_v8::activation_attestation_v1::Request,
        admission:u32,class:u8)->Result<ChallengeFrame>{
        let result=(||{let frames=self.receive(MAX_FRAME)?;
            self.channel.open_requested_challenge(request,admission,class,&frames)})();self.finish(result)
    }
    pub fn send_response(&mut self,expected:&ChallengeFrame,response:&ResponseFrame)->Result<()> {
        let result=(||{self.remaining()?;let frames=self.channel.seal_response(expected,response)?;self.send(frames)})();self.finish(result)
    }
    pub fn receive_response(&mut self,expected:&ChallengeFrame)->Result<ResponseFrame>{
        let result=(||{let frames=self.receive(512)?;self.channel.open_response(expected,&frames)})();self.finish(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use zeroize::Zeroizing;
    fn connected()->(TcpStream,TcpStream){
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let a=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (b,_)=listener.accept().unwrap();(a,b)
    }
    #[test]
    fn actual_tcp_private_exchange_uses_authenticated_frames(){
        let (a,b)=connected();let (ac,bc)=super::super::channel::tests::pair();
        let mut a=PrivateSocket::new(a,ac,Duration::from_secs(5)).unwrap();
        let mut b=PrivateSocket::new(b,bc,Duration::from_secs(5)).unwrap();
        std::thread::scope(|scope|{
            let peer=scope.spawn(move||{
                let expected=super::super::exchange::tests::frame();
                b.receive_challenge(&expected).unwrap();
                let response=ResponseFrame::new(&expected,vec![Zeroizing::new([10;32]),Zeroizing::new([11;32])]).unwrap();
                b.send_response(&expected,&response).unwrap();
            });
            let expected=super::super::exchange::tests::frame();
            a.send_challenge(&expected).unwrap();let actual=a.receive_response(&expected).unwrap();
            let correct=ResponseFrame::new(&expected,vec![Zeroizing::new([10;32]),Zeroizing::new([11;32])]).unwrap();
            assert_eq!(actual.encode_private().unwrap().as_slice(),correct.encode_private().unwrap().as_slice());
            peer.join().unwrap();
        });
    }
    #[test]
    fn actual_tcp_zero_oversize_partial_and_expiry_poison_connection(){
        // Public malformed encrypted-record headers, not fabricated private success.
        for header in [vec![0,0],vec![0xff,0xff],vec![0,1,0,0],vec![0,1,0,116,1,2]] {
            let (a,mut b)=connected();let (ac,_)=super::super::channel::tests::pair();
            b.write_all(&header).unwrap();b.shutdown(std::net::Shutdown::Both).unwrap();
            let mut a=PrivateSocket::new(a,ac,Duration::from_secs(5)).unwrap();
            let expected=super::super::exchange::tests::frame();
            assert!(a.receive_response(&expected).is_err());assert!(a.poisoned);
            assert!(matches!(a.send_challenge(&expected),Err(Error::Endpoint)));
        }
        let (a,_)=connected();let (ac,_)=super::super::channel::tests::pair();
        let mut a=PrivateSocket::new(a,ac,Duration::from_secs(5)).unwrap();
        // Exact already-expired boundary, no timing inflation or timer-success.
        a.deadline=Instant::now();
        assert!(matches!(a.send_challenge(&super::super::exchange::tests::frame()),Err(Error::Expired)));
        assert!(a.poisoned);
    }
}
