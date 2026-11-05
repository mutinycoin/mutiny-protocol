//! Two-phase public Genesis construction. This is NOT the production ceremony:
//! final protocol, physical enrollment, complete state and independent seal gates
//! must all pass before a node is allowed to install the candidate artifact.
use crate::{Error, Hash, Result, blocks::GenesisDescriptor};

#[derive(Clone, Debug)]
pub struct GenesisIdentity {
    descriptor: GenesisDescriptor,
    bytes: Vec<u8>,
    id: Hash,
}
impl GenesisIdentity {
    /// Freeze a canonical descriptor in memory, before Worker enrollment.
    /// Production ceremony must durably freeze these exact bytes as well.
    pub fn new(descriptor: GenesisDescriptor) -> Result<Self> {
        let bytes = descriptor.encode()?;
        let id = descriptor.id()?;
        Ok(Self {
            descriptor,
            bytes,
            id,
        })
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn descriptor(&self) -> &GenesisDescriptor {
        &self.descriptor
    }
    /// Changed identity inputs invalidate this phase; never silently rederive
    /// an identity under which enrollment messages were already signed.
    pub fn verify_unchanged(&self, descriptor: &GenesisDescriptor) -> Result<()> {
        if descriptor.encode()? != self.bytes {
            return Err(Error::WrongGenesis);
        }
        Ok(())
    }
    pub fn bind_workers(
        &self,
        bindings: &[crate::licenses::BindWorker],
    ) -> Result<crate::licenses::LicenseBook> {
        crate::licenses::LicenseBook::genesis_bindings(
            self.id,
            self.descriptor.fingerprint,
            self.descriptor.owner,
            self.descriptor.purchase,
            bindings,
        )
    }
}
