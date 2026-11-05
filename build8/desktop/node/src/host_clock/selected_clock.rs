//! Ordinary owning clock facade. Native approval factories remain absent.
//! This module supplies task/consumer ownership, never deployment authority.
use super::{ChronyClock,HostClock,HostClockConfig,NativeClock,NativeClockStop};
use mutiny_consensus_v8::{holdover_clock_v1::TimeBasis,
    vote_clock_v1::{ClockReading,VoteClock}};
use std::sync::{Arc,Mutex};
type Result<T>=std::result::Result<T,String>;
const NATIVE_SCHEMA:&str="BUILD8-NATIVE-NTS-CLOCK-V1";
struct RevocableBasis {inner:Arc<dyn TimeBasis>,stopped:Mutex<bool>}
impl TimeBasis for RevocableBasis {
    fn lower_bound_ms(&self)->Option<u64> {
        let stopped=self.stopped.lock().ok()?;
        if *stopped{return None;}
        self.inner.lower_bound_ms()
    }
}
impl VoteClock for RevocableBasis {
    fn reading(&self)->ClockReading {
        match self.lower_bound_ms() {
            Some(ms)=>ClockReading::Qualified{utc_seconds:ms/1000},
            None=>ClockReading::Unqualified,
        }
    }
}
enum Owner {
    Chrony(ChronyClock),
    Native {stop:NativeClockStop,task:Option<std::thread::JoinHandle<Result<()>>>},
}
pub struct SelectedClock {
    basis:Arc<RevocableBasis>,owner:Owner,
    // Exact bytes successfully selected by the independent installed adapter;
    // never a caller assertion or an anchor-derived installation capability.
    native_record:Option<Vec<u8>>,
}
fn declaration(value:&serde_json::Value)->Result<Vec<u8>> {
    let map=value.as_object().ok_or("native clock declaration object")?;
    if map.len()!=2 || !map.contains_key("record") || value["schema"]!=NATIVE_SCHEMA
        || map.keys().any(|k|k!="schema"&&k!="record") {
        return Err("native clock declaration fields".into());
    }
    // serde-json map order is not an approval mechanism. Decoder rechecks the
    // complete exact canonical artifact against independently accepted bytes.
    let raw=serde_json::to_vec(&value["record"]).map_err(|_|"native record serialization")?;
    if raw.is_empty()||raw.len()>64*1024{return Err("native record bound".into());}
    Ok(raw)
}
impl SelectedClock {
    pub fn is_native_declaration(value:&serde_json::Value)->bool {
        value.get("schema").and_then(|v|v.as_str())==Some(NATIVE_SCHEMA)
    }
    pub fn start_chrony(config:HostClockConfig)->Result<Self> {
        let host=HostClock::start(config)?;
        Ok(Self {basis:Arc::new(RevocableBasis {inner:host.basis(),stopped:Mutex::new(false)}),
            owner:Owner::Chrony(host),native_record:None})
    }
    /// Canonical record selection stays inside the existing trusted-input
    /// adapter. Caller bytes/path/numbers cannot install receipts or profiles.
    pub fn start_native(value:&serde_json::Value,own_genesis:&[u8])->Result<Self> {
        let record=declaration(value)?;
        let clock=super::native_nts_startup::start_installed(&record,own_genesis)?;
        Self::own_native(clock,record)
    }
    /// Preflight rejection preserves the old selection. Once the predecessor
    /// preflight succeeds and stop begins, any replacement failure leaves the
    /// original service and surviving consumer Arcs revoked. The old owner is
    /// naturally joined before the new route can restore or acquire. Its
    /// greatest consumed clock floor is first written to the existing durable
    /// lineage under the old service barrier. A successor must use that exact
    /// anchor/mark; switching to a new empty clock anchor is refused. No signer
    /// locks, reservations, counters or halt records are accessible here.
    pub fn replace_native(&mut self,value:&serde_json::Value,own_genesis:&[u8])->Result<()> {
        let record=declaration(value)?;
        let prior=self.native_record.as_deref().ok_or("native replacement requires an accepted native predecessor")?;
        super::native_nts_deployment_record::require_successor(prior,&record)
            .map_err(|e|format!("native replacement succession refused: {e:?}"))?;
        self.revoke_basis();
        let continuity=match &self.owner {
            Owner::Native {stop,..}=>stop.freeze_for_replacement(),
            Owner::Chrony(_)=>Err("native replacement requires a native owner".into()),
        };
        // Always cancel/join even when durable retirement fails. No successor
        // starts until BOTH the handoff and natural predecessor closure succeed.
        let closure=self.stop();
        let continuity=match (continuity,closure) {
            (Ok(continuity),Ok(()))=>continuity,
            (Err(error),Ok(()))=>return Err(error),
            (Ok(_),Err(error))=>return Err(error),
            (Err(_),Err(_))=>return Err("native replacement retirement and shutdown refused".into()),
        };
        // This authorization is still mandatory: a correctly chained caller
        // record cannot substitute for the administrator's installed pins,
        // genuine qualified evidence, or independently observed current facts.
        let clock=super::native_nts_startup::start_installed_replacement(&record,own_genesis,continuity)?;
        let replacement=Self::own_native(clock,record)?;
        *self=replacement;
        Ok(())
    }
    fn own_native(clock:NativeClock,record:Vec<u8>)->Result<Self> {
        let basis=Arc::new(RevocableBasis {inner:clock.basis(),stopped:Mutex::new(false)});
        let stop=clock.stop_handle();
        // Build failure or spawn failure drops the service/held owner and
        // poisons every surviving native consumer; no detached acquisition.
        let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()
            .map_err(|_|"native clock runtime creation failed")?;
        let task=std::thread::Builder::new().name("native-clock-owned".into())
            .spawn(move||runtime.block_on(clock.run()))
            .map_err(|_|"native clock task creation failed")?;
        Ok(Self {basis,owner:Owner::Native {stop,task:Some(task)},native_record:Some(record)})
    }
    pub fn basis(&self)->Arc<dyn TimeBasis> {self.basis.clone()}
    pub fn vote_clock(&self)->Arc<dyn VoteClock> {self.basis.clone()}
    pub fn check_alive(&mut self)->Result<()> {
        if let Owner::Chrony(host)=&self.owner {
            if !host.alive() {
                let closure=self.stop();
                return Err(closure.err().unwrap_or_else(||"host clock task ended unexpectedly".into()));
            }
        }
        if let Owner::Native {task,..}=&self.owner {
            if task.as_ref().is_none_or(|t|t.is_finished()) {
                let closure=self.stop();
                return Err(closure.err().unwrap_or_else(||"native clock task ended unexpectedly".into()));
            }
        }
        Ok(())
    }
    fn revoke_basis(&self) {
        match self.basis.stopped.lock() {
            Ok(mut stopped)=>*stopped=true,
            Err(poisoned)=>*poisoned.into_inner()=true,
        }
    }
    /// Revokes all retained consumers first, then cancels and naturally joins
    /// the selected owned service. Never signals, detaches or steals a store lock.
    pub fn stop(&mut self)->Result<()> {
        self.revoke_basis();
        match &mut self.owner {
            Owner::Chrony(host)=>host.stop(),
            Owner::Native {stop,task}=>{
                stop.stop();
                match task.take() {
                    None=>Ok(()),
                    Some(task)=>task.join().map_err(|_|"native clock task panicked".to_owned())?,
                }
            }
        }
    }
}
impl Drop for SelectedClock {
    fn drop(&mut self) {
        if self.stop().is_err(){eprintln!("selected clock natural shutdown refused");}
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn native_declaration_does_not_grant_missing_accepted_inputs() {
        let value=serde_json::json!({"schema":NATIVE_SCHEMA,"record":{}});
        let error=SelectedClock::start_native(&value,b"untrusted-genesis").err().unwrap();
        assert!(error.ends_with("MissingAcceptedInputs"));
    }
    #[test] fn declaration_refuses_other_shapes_without_defaults() {
        for value in [serde_json::json!({}),serde_json::json!({"schema":NATIVE_SCHEMA}),
            serde_json::json!({"schema":NATIVE_SCHEMA,"record":{},"approval":true}),
            serde_json::json!({"schema":"other","record":{}})] {
            assert!(declaration(&value).is_err());
        }
    }
}
