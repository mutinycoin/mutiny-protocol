//! Actual native software observations only. These cannot construct accepted
//! deployment pins, measured-boot proof or a CurrentNativeInputs receipt.
use super::native_nts_deployment_record::DecodedRecord;

#[derive(Clone)]
pub(super) struct NativeSoftwareCapture {
    boot: super::windows_boot::BootEnvironment,
    first: (u64,u64,u128),
    second: (u64,u64,u128),
}
impl NativeSoftwareCapture {
    pub(super) fn boot(&self)->&super::windows_boot::BootEnvironment { &self.boot }
    pub(super) fn elapsed_samples(&self)->((u64,u64,u128),(u64,u64,u128)) {
        (self.first,self.second)
    }
}
/// Software continuity evidence only, owned by the opaque current receipt and
/// carried through placement. A native capture never approves a deployment.
#[derive(Clone)]
pub(super) enum CurrentSoftwareBoundary {
    Captured(NativeSoftwareCapture),
    #[cfg(all(target_os="linux",target_arch="x86_64"))]
    Linux(std::sync::Arc<std::sync::Mutex<super::native_nts_linux_current::LinuxBoundary>>),
    #[cfg(all(windows,target_arch="x86_64"))]
    Windows(std::sync::Arc<std::sync::Mutex<super::native_nts_windows_current::WindowsBoundary>>),
    #[cfg(test)]
    Modeled,
}
pub(super) enum CurrentRetainedClose {
    Native {report:super::native_retained_close::RetainedCloseReport,poisoned:bool},
    Quarantined(std::mem::ManuallyDrop<CurrentSoftwareBoundary>),
    #[cfg(all(target_os="linux",target_arch="x86_64"))]
    LinuxQuarantined(std::mem::ManuallyDrop<super::native_nts_linux_current::LinuxBoundary>),
    #[cfg(all(windows,target_arch="x86_64"))]
    WindowsQuarantined(std::mem::ManuallyDrop<super::native_nts_windows_current::WindowsBoundary>),
    NoNativeObjects,
}
impl CurrentRetainedClose {
    pub(super) fn retained_handles_closed(&self)->bool {
        match self {Self::Native{report,poisoned}=>!*poisoned&&report.retained_handles_closed(),
            Self::NoNativeObjects=>true,_=>false}
    }
}
impl CurrentSoftwareBoundary {
    /// Consuming last-owner close. A shared observer remains retained, never
    /// treated as closed or replaced. This asserts only explicit held objects.
    pub(super) fn close_retained(self)->CurrentRetainedClose {
        match self {
            #[cfg(all(target_os="linux",target_arch="x86_64"))]
            Self::Linux(owner)=>{
                let mutex=match std::sync::Arc::try_unwrap(owner){Ok(m)=>m,Err(owner)=>return CurrentRetainedClose::Quarantined(std::mem::ManuallyDrop::new(Self::Linux(owner)))};
                let (boundary,poisoned)=match mutex.into_inner(){Ok(b)=>(b,false),Err(p)=>(p.into_inner(),true)};
                match boundary.close_retained(){Ok(report)=>CurrentRetainedClose::Native{report,poisoned},
                    Err(boundary)=>CurrentRetainedClose::LinuxQuarantined(std::mem::ManuallyDrop::new(boundary))}
            },
            #[cfg(all(windows,target_arch="x86_64"))]
            Self::Windows(owner)=>{
                let mutex=match std::sync::Arc::try_unwrap(owner){Ok(m)=>m,Err(owner)=>return CurrentRetainedClose::Quarantined(std::mem::ManuallyDrop::new(Self::Windows(owner)))};
                let (boundary,poisoned)=match mutex.into_inner(){Ok(b)=>(b,false),Err(p)=>(p.into_inner(),true)};
                match boundary.close_retained(){Ok(report)=>CurrentRetainedClose::Native{report,poisoned},
                    Err(boundary)=>CurrentRetainedClose::WindowsQuarantined(std::mem::ManuallyDrop::new(boundary))}
            },
            Self::Captured(_)=>CurrentRetainedClose::NoNativeObjects,
            #[cfg(test)]Self::Modeled=>CurrentRetainedClose::NoNativeObjects,
        }
    }
    /// This is a software receipt only. It is usable by the ordinary installed
    /// pipeline after its separate mandatory physical qualification gate.
    /// A diagnostic capture or legacy Linux primary-image pin cannot
    /// supply loaded-code authority through this method.
    pub(super) fn require_selected_loaded(&mut self,record:&DecodedRecord)->Result<(),()> {
        match self {
            #[cfg(all(target_os="linux",target_arch="x86_64"))]
            Self::Linux(owner)=>owner.lock().map_err(|_|())?.require_loaded(record).map_err(|_|()),
            #[cfg(all(windows,target_arch="x86_64"))]
            Self::Windows(owner)=>owner.lock().map_err(|_|())?.require_loaded(record).map_err(|_|()),
            _=>Err(()),
        }
    }
    pub(super) fn recheck(&mut self, record:&DecodedRecord)->Result<(),()> {
        match self {
            Self::Captured(before)=>before.advance(capture(record)?),
            #[cfg(all(windows,target_arch="x86_64"))]
            Self::Windows(owner)=>owner.lock().map_err(|_|())?.require_loaded(record).map_err(|_|()),
            #[cfg(all(target_os="linux",target_arch="x86_64"))]
            Self::Linux(owner)=>owner.lock().map_err(|_|())?.require_loaded(record).map_err(|_|()),
            #[cfg(test)]
            Self::Modeled=>Ok(()), // Explicit private TEST model, no native credit.
        }
    }
}
impl NativeSoftwareCapture {
    // Advance only after validating against the LAST accepted capture. Keeping
    // startup forever would miss a later regression still above startup.
    // Failure leaves the exact prior capture intact; service revocation is sticky.
    fn advance(&mut self, after:Self)->Result<(),()> {
        self.check_successor(&after)?;
        *self=after;
        Ok(())
    }
    pub(super) fn check_successor(&self, after:&Self)->Result<(),()> {
        // Both snapshots already passed the same boot/sample validator. Require
        // continuity from the last accepted LAST sample to the fresh FIRST sample;
        // comparing only fresh.last would mask an intervening regression.
        if self.boot!=after.boot || after.first.0<self.second.0
            || after.first.1<self.second.1 { return Err(()); }
        Ok(())
    }
}
pub(super) fn capture(record:&DecodedRecord)->Result<NativeSoftwareCapture,()> {
    // Existing bounds, exact version-pinned OS query, no random/wall-time or
    // alternative-provider fallback. No native code is executed at construction
    // of the installed selection (which is currently absent).
    let span=record.acquisition().bounds.maximum_sampling_span_ns;
    let before=super::windows_boot::read().map_err(|_|())?;
    let first=mutiny_clock_native_nts_v1::read_elapsed(span).ok_or(())?;
    let second=mutiny_clock_native_nts_v1::read_elapsed(span).ok_or(())?;
    let after=super::windows_boot::read().map_err(|_|())?;
    checked(before,after,first,second)
}
/// Independently invoke the existing boot/elapsed implementation, then compare
/// its actual OS/build/boot parameters and exact ABI to the decoded contract.
/// This is diagnostic context matching, not a qualification/current issuer.
pub(super) fn capture_bound(record:&DecodedRecord,
    contract:&super::native_nts_qualification::CurrentContract)
    ->Result<NativeSoftwareCapture,()> {
    let observed=capture(record)?;
    contract.compare_windows_diagnostic(observed.boot()).map_err(|_|())?;
    Ok(observed)
}
pub(super) fn capture_current_bound(record:&DecodedRecord,
    contract:&super::native_nts_qualification::CurrentContract)->Result<CurrentSoftwareBoundary,()> {
    if contract.is_linux() {
        #[cfg(all(target_os="linux",target_arch="x86_64"))]
        {return Ok(CurrentSoftwareBoundary::Linux(std::sync::Arc::new(std::sync::Mutex::new(
            super::native_nts_linux_current::LinuxBoundary::open(record,contract).map_err(|_|())?))));}
        #[cfg(not(all(target_os="linux",target_arch="x86_64")))]
        {return Err(());}
    }
    #[cfg(all(windows,target_arch="x86_64"))]
    {return Ok(CurrentSoftwareBoundary::Windows(std::sync::Arc::new(std::sync::Mutex::new(
        super::native_nts_windows_current::WindowsBoundary::open(record,contract).map_err(|_|())?))));}
    #[cfg(not(all(windows,target_arch="x86_64")))]
    {Err(())}
}
fn checked(before:super::windows_boot::BootEnvironment,
    after:super::windows_boot::BootEnvironment,first:(u64,u64,u128),second:(u64,u64,u128))
    ->Result<NativeSoftwareCapture,()> {
    let boot=u128::from_le_bytes(before.identifier_bytes);
    if before!=after || boot==0 || first.2!=boot || second.2!=boot
        || first.0==0 || first.1==0 || second.0<first.0 || second.1<first.1
        || first.1<first.0 || second.1<second.0 { return Err(()); }
    Ok(NativeSoftwareCapture {boot:before,first,second})
}
#[cfg(test)]
mod tests {
    use super::*;
    fn boot()->super::super::windows_boot::BootEnvironment {
        super::super::windows_boot::BootEnvironment {identifier_bytes:[1;16],
            firmware_type:2,boot_flags:0,os_build:26200}
    }
    #[test] fn modeled_capture_requires_stable_boot_and_nonregressing_native_samples() {
        let b=boot();let id=u128::from_le_bytes(b.identifier_bytes);
        let c=checked(b.clone(),b.clone(),(100,110,id),(101,112,id)).unwrap();
        assert_eq!(c.boot(),&b);assert_eq!(c.elapsed_samples(),((100,110,id),(101,112,id)));
        let mut different=b.clone();different.identifier_bytes[0]=2;
        assert!(checked(b.clone(),different,(100,110,id),(101,112,id)).is_err());
        for (first,second) in [((0,110,id),(101,112,id)),((100,99,id),(101,112,id)),
            ((100,110,id),(99,112,id)),((100,110,id),(101,109,id)),
            ((100,110,id),(101,112,id+1))] {
            assert!(checked(b.clone(),b.clone(),first,second).is_err());
        }
    }
    #[test] fn modeled_continuous_current_gate_advances_and_refuses_between_check_regression() {
        let b=boot();let id=u128::from_le_bytes(b.identifier_bytes);
        let mut at=checked(b.clone(),b.clone(),(100,110,id),(101,112,id)).unwrap();
        let advanced=checked(b.clone(),b.clone(),(200,210,id),(201,212,id)).unwrap();
        at.advance(advanced).unwrap();
        let retired=checked(b.clone(),b.clone(),(150,160,id),(151,162,id)).unwrap();
        assert!(at.advance(retired).is_err());
        assert_eq!(at.elapsed_samples(),((200,210,id),(201,212,id)));
        let mut changed=b.clone();changed.os_build+=1;
        assert!(at.advance(checked(changed.clone(),changed,(202,213,id),(203,214,id)).unwrap()).is_err());
        assert_eq!(at.boot(),&b);
        assert_eq!(at.elapsed_samples(),((200,210,id),(201,212,id)));
        at.advance(checked(b.clone(),b,(201,212,id),(202,213,id)).unwrap()).unwrap();
        assert_eq!(at.elapsed_samples(),((201,212,id),(202,213,id)));
    }
    #[test] fn modeled_current_capture_requires_fresh_same_os_boot_and_elapsed_continuity() {
        let b=boot();let id=u128::from_le_bytes(b.identifier_bytes);
        let original=checked(b.clone(),b.clone(),(100,110,id),(101,112,id)).unwrap();
        let good=checked(b.clone(),b.clone(),(101,112,id),(102,113,id)).unwrap();
        assert!(original.check_successor(&good).is_ok());
        for (first,second) in [((100,112,id),(102,113,id)),((101,111,id),(102,113,id))] {
            let later=checked(b.clone(),b.clone(),first,second).unwrap();
            assert!(original.check_successor(&later).is_err());
        }
        for field in 0..4 {
            let mut changed=b.clone();match field {
                0=>changed.identifier_bytes[0]^=2,1=>changed.os_build+=1,
                2=>changed.firmware_type+=1,_=>changed.boot_flags^=1,
            }
            let changed_id=u128::from_le_bytes(changed.identifier_bytes);
            let later=checked(changed.clone(),changed,(101,112,changed_id),(102,113,changed_id)).unwrap();
            assert!(original.check_successor(&later).is_err());
        }
    }

}
