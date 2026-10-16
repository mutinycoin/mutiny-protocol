// EXTERNAL SOURCE-ONLY: serialized nonshipping service budget, no native action implementation.
use super::control_codec::Role;
pub const MAX_CONNECTIONS: usize = 3;
pub const MAX_ROLE_REQUESTS: u64 = 128;
pub const MAX_CAMPAIGN_REQUESTS: u64 = 384;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Connected, NotConnected, Busy, Sequence, Budget }
#[derive(Clone, Copy, Default)]
struct Slot { connected: bool, busy: bool, consumed: u64 }
pub struct Budget { slots: [Slot;3], consumed: u64 }
impl Budget {
    pub fn new()->Self {Self{slots:[Slot::default();3],consumed:0}}
    fn index(role:Role)->usize {role as usize-1}
    // Authenticated PID/bootstrap matching happens independently BEFORE connect.
    pub fn connect(&mut self,role:Role)->Result<u64,Error> {
        let s=&mut self.slots[Self::index(role)];
        if s.connected {return Err(Error::Connected);}
        if s.busy {return Err(Error::Busy);}
        if s.consumed>=MAX_ROLE_REQUESTS || self.consumed>=MAX_CAMPAIGN_REQUESTS {return Err(Error::Budget);}
        s.connected=true;Ok(s.consumed+1)
    }
    // Called only AFTER authenticated channel + full bounded syntax/pins/head.
    // Semantic/native action refusal still consumes sequence; no success replay cache.
    pub fn begin(&mut self,role:Role,sequence:u64)->Result<(),Error> {
        let s=&mut self.slots[Self::index(role)];
        if !s.connected {return Err(Error::NotConnected);}
        if s.busy {return Err(Error::Busy);}
        if sequence==0 || sequence!=s.consumed+1 {return Err(Error::Sequence);}
        if s.consumed>=MAX_ROLE_REQUESTS || self.consumed>=MAX_CAMPAIGN_REQUESTS {return Err(Error::Budget);}
        s.consumed+=1;self.consumed+=1;s.busy=true;Ok(())
    }
    // Finish means action attempt ended, never that any block/delivery succeeded.
    pub fn finish(&mut self,role:Role)->Result<(),Error> {
        let s=&mut self.slots[Self::index(role)];
        if !s.connected {return Err(Error::NotConnected);}
        if !s.busy {return Err(Error::Sequence);}
        s.busy=false;Ok(())
    }
    pub fn disconnect(&mut self,role:Role)->Result<(),Error> {
        let s=&mut self.slots[Self::index(role)];
        if !s.connected {return Err(Error::NotConnected);}
        if s.busy {return Err(Error::Busy);}
        s.connected=false;Ok(())
    }
    pub fn next_sequence(&self,role:Role)->Result<u64,Error> {
        let s=&self.slots[Self::index(role)];
        if !s.connected {return Err(Error::NotConnected);}
        if s.busy {return Err(Error::Busy);}
        if s.consumed>=MAX_ROLE_REQUESTS || self.consumed>=MAX_CAMPAIGN_REQUESTS {return Err(Error::Budget);}
        Ok(s.consumed+1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn sequence_is_not_reset_by_authenticated_reconnect() {
        let mut b=Budget::new();assert_eq!(b.connect(Role::WalletA),Ok(1));
        assert_eq!(b.connect(Role::WalletA),Err(Error::Connected));
        b.begin(Role::WalletA,1).unwrap();assert_eq!(b.disconnect(Role::WalletA),Err(Error::Busy));
        b.finish(Role::WalletA).unwrap();b.disconnect(Role::WalletA).unwrap();
        assert_eq!(b.connect(Role::WalletA),Ok(2));assert_eq!(b.begin(Role::WalletA,1),Err(Error::Sequence));
        b.begin(Role::WalletA,2).unwrap();b.finish(Role::WalletA).unwrap();
    }
    #[test] fn per_role_and_whole_campaign_bounds_exact() {
        let mut b=Budget::new();
        for role in [Role::WalletA,Role::WalletC,Role::Treasury] {
            b.connect(role).unwrap();
            for seq in 1..=128 {b.begin(role,seq).unwrap();b.finish(role).unwrap();}
            assert_eq!(b.next_sequence(role),Err(Error::Budget));assert_eq!(b.begin(role,129),Err(Error::Budget));
        }
        assert_eq!(b.consumed,384);
    }
    #[test] fn no_inflight_reentry_and_invalid_sequence_consumes_nothing() {
        let mut b=Budget::new();b.connect(Role::WalletA).unwrap();
        for sequence in [0,2,u64::MAX] {assert_eq!(b.begin(Role::WalletA,sequence),Err(Error::Sequence));}
        assert_eq!(b.next_sequence(Role::WalletA),Ok(1));b.begin(Role::WalletA,1).unwrap();
        assert_eq!(b.begin(Role::WalletA,2),Err(Error::Busy));b.finish(Role::WalletA).unwrap();
        assert_eq!(b.next_sequence(Role::WalletA),Ok(2));
    }
}
