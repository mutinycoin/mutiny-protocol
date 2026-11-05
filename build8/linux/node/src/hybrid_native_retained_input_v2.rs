//! Root original file ownership BEFORE native acquisition, then use the same
//! reviewed once-only close report. This is custody only, never an installer,
//! path/protection/current-code/peer/qualification issuer.
use crate::host_clock::{retained_identity,RetainedCloseReport};
use std::{fs::File,mem::ManuallyDrop};

struct State {
    file:Option<ManuallyDrop<File>>,
    original:Option<[u8;24]>,
    close:Option<RetainedCloseReport>,
}
/// Allocate this slot before openat/getsockopt/recvmsg/dup/CreateFile effects.
/// A failed initial identity capture retains the ORIGINAL File in this slot;
/// it cannot be reconstructed or closed using a guessed native identity.
pub(crate) struct RetainedNativeFile {state:ManuallyDrop<Box<State>>}
pub(crate) struct NativeInputSlot {state:Option<ManuallyDrop<Box<State>>>}
pub(crate) struct RetainedInputFailure {
    pub(crate) owner:ManuallyDrop<RetainedNativeFile>,
    pub(crate) cause:String,
}
impl NativeInputSlot {
    pub(crate) fn prepare()->Result<Self,String> {
        let close=RetainedCloseReport::prepare(1)?;
        Ok(Self{state:Some(ManuallyDrop::new(Box::new(State{
            file:None,original:None,close:Some(close),
        })))})
    }
    /// Only the caller performing the original native acquisition may move
    /// its File here. Publish BEFORE any identity/security/read operation.
    pub(crate) fn retain(mut self,file:File)->Result<RetainedNativeFile,RetainedInputFailure> {
        let mut owner=RetainedNativeFile{state:self.state.take().expect("exclusive unused native input slot")};
        owner.state.file=Some(ManuallyDrop::new(file));
        let original=match retained_identity(&**owner.state.file.as_ref().expect("published original file")) {
            Ok(value)=>value,Err(_)=>return Err(RetainedInputFailure{
                owner:ManuallyDrop::new(owner),cause:"original native input identity unavailable".into(),
            }),
        };
        owner.state.original=Some(original);Ok(owner)
    }
}
impl Drop for NativeInputSlot {
    fn drop(&mut self){if let Some(mut state)=self.state.take(){unsafe{ManuallyDrop::drop(&mut state)};}}
}
impl RetainedNativeFile {
    pub(crate) fn file(&self)->Result<&File,String> {
        self.state.file.as_ref().map(|file|&**file)
            .ok_or_else(||"original native input absent".into())
    }
    pub(crate) fn original_identity(&self)->Result<[u8;24],String> {
        self.state.original.ok_or_else(||"original native input identity absent".into())
    }
    /// An identity mismatch does not close or replace the original input.
    pub(crate) fn recheck_identity(&self)->Result<(),String> {
        if retained_identity(self.file()?).map_err(|_|"native input current identity unavailable")?
            !=self.original_identity()? {
            return Err("original native input identity changed".into());
        }Ok(())
    }
    /// Ok(report) is the observation of ONE close, not a success Boolean.
    /// The consumer must require report.retained_handles_closed(). Unknown
    /// outcomes preserve the report's original identity/error records.
    pub(crate) fn close_once(mut self)->Result<RetainedCloseReport,ManuallyDrop<Self>> {
        let original=match self.state.original {Some(value)=>value,None=>return Err(ManuallyDrop::new(self))};
        if self.state.file.is_none()||self.state.close.is_none() {
            return Err(ManuallyDrop::new(self));
        }
        let mut close=self.state.close.take().expect("checked original close report");
        let file=self.state.file.take().expect("checked original file");
        close.file(ManuallyDrop::into_inner(file),original);
        Ok(close)
    }
}
impl Drop for RetainedNativeFile {
    fn drop(&mut self) {
        if self.state.file.is_none() {
            // Allocation/empty preentry or already consumed known observation;
            // no native handle exists here to retry or implicitly release.
            unsafe{ManuallyDrop::drop(&mut self.state)};
        }
        // Otherwise retain the already allocated complete original holder on
        // abandonment/unwind, including failed original-ID capture. No late
        // Box allocation, close, FD reopening or fabricated outcome occurs.
    }
}
