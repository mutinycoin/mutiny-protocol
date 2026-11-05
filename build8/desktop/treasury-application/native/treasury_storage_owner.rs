//! UNCOMPILED private Treasury typed-store bridge. No registration/factory.
//! Storage ownership complements, never replaces, the adopted current-service
//! complete-history check. A recovered-copy Store must remain semantically
//! frozen until the existing continuity owner authenticates/reconciles it.
use crate::treasury_rehearsal_v3::{Outcome,Refusal};
use rusqlite::Connection;
use crate::treasury_bounded_readers::WorkSlot;
#[cfg(target_os="linux")]
use super::protected_owner::{Owner,NativeBoundary,Error};
#[cfg(windows)]
use super::windows_sqlite_owner::{Owner,NativeBoundary,Error};
pub(crate) struct Storage { owner:Owner }
fn refused(_:Error)->Refusal{Refusal::Store}
pub(crate) struct BeforeExternal<'a> { boundary:&'a NativeBoundary<'a> }
impl BeforeExternal<'_>{
    pub(crate) fn check(&self)->Outcome<()>{self.boundary.status().map_err(refused)}
}
impl Storage {
    /// Only an opaque actual OS/VFS owner, never a Connection/caller identity,
    /// can enter this bridge. This is not a deployment eligibility constructor.
    pub(crate) fn from_native_candidate(owner:Owner)->Self{Self{owner}}
    pub(crate) fn status(&self)->Outcome<()>{self.owner.status().map_err(refused)}
    pub(crate) fn read<R>(&self,action:impl FnOnce(&Connection,&WorkSlot)->Outcome<R>)->Outcome<R>{
        self.owner.inspect_typed(refused,action)
    }
    pub(crate) fn write<R>(&mut self,action:impl FnOnce(&mut Connection,&BeforeExternal<'_>,&WorkSlot)->Outcome<R>)->Outcome<R>{
        self.owner.mutate_typed(refused,|db,boundary,slot|action(db,&BeforeExternal{boundary},slot))
    }
    pub(crate) fn close(self)->Result<(),(Self,Refusal)>{
        self.owner.close().map_err(|(owner,error)|(Self{owner},refused(error)))
    }
}
