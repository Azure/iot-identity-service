pub use esys_sys::ESYS_TR;

use std::fmt;

use crate::{private, EsysContext};

pub trait TpmResource: private::Sealed {
    fn tr(&self) -> ESYS_TR;
}

#[derive(Debug, Eq, PartialEq)]
pub enum Handle<'a> {
    Fixed(FixedHandle),
    Transient(TransientHandle<'a>),
}

impl<'a> Handle<'a> {
    pub fn fixed(index: ESYS_TR) -> Self {
        Self::Fixed(FixedHandle(index))
    }

    pub fn transient(index: ESYS_TR, context: &'a EsysContext) -> Self {
        Self::Transient(TransientHandle { index, context })
    }
}

impl private::Sealed for Handle<'_> {}

impl TpmResource for Handle<'_> {
    fn tr(&self) -> ESYS_TR {
        match self {
            Self::Fixed(handle) => handle.tr(),
            Self::Transient(handle) => handle.tr(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedHandle(ESYS_TR);

impl FixedHandle {
    pub const NONE: Self = Self(esys_sys::ESYS_TR_NONE);
    pub const PASSWORD: Self = Self(esys_sys::ESYS_TR_PASSWORD);

    const OWNER_HIERARCHY: Self = Self(esys_sys::ESYS_TR_RH_OWNER);
    const NULL_HIERARCHY: Self = Self(esys_sys::ESYS_TR_RH_NULL);
    const ENDORSEMENT_HIERARCHY: Self = Self(esys_sys::ESYS_TR_RH_ENDORSEMENT);
    const PLATFORM_HIERARCHY: Self = Self(esys_sys::ESYS_TR_RH_PLATFORM);
}

impl private::Sealed for FixedHandle {}

impl TpmResource for FixedHandle {
    fn tr(&self) -> ESYS_TR {
        self.0
    }
}

pub struct TransientHandle<'a> {
    index: ESYS_TR,
    context: &'a EsysContext,
}

impl PartialEq for TransientHandle<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && std::ptr::eq(self.context, other.context)
    }
}

impl Eq for TransientHandle<'_> {}

impl private::Sealed for TransientHandle<'_> {}

impl TpmResource for TransientHandle<'_> {
    fn tr(&self) -> ESYS_TR {
        self.index
    }
}

impl fmt::Debug for TransientHandle<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TransientHandle").field(&self.index).finish()
    }
}

impl Drop for TransientHandle<'_> {
    fn drop(&mut self) {
        let handle = std::mem::replace(&mut self.index, esys_sys::ESYS_TR_NONE);
        if let Err(e) = self.context.flush(handle) {
            log::error!("could not flush TransientHandle(0x{:08X}): {}", handle, e);
        }
    }
}

#[derive(Debug)]
pub struct AuthSession<'a>(pub(crate) Handle<'a>);

impl AuthSession<'_> {
    pub const PASSWORD: Self = Self(Handle::Fixed(FixedHandle::PASSWORD));

    pub fn with_policy(mut self, policy: crate::Policy) -> crate::Result<Self> {
        policy.apply(&mut self)?;

        Ok(self)
    }
}

impl private::Sealed for AuthSession<'_> {}

impl TpmResource for AuthSession<'_> {
    fn tr(&self) -> esys_sys::ESYS_TR {
        self.0.tr()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Hierarchy(FixedHandle);

impl Hierarchy {
    pub const OWNER: Self = Self(FixedHandle::OWNER_HIERARCHY);
    pub const NULL: Self = Self(FixedHandle::NULL_HIERARCHY);
    pub const ENDORSEMENT: Self = Self(FixedHandle::ENDORSEMENT_HIERARCHY);
    pub const PLATFORM: Self = Self(FixedHandle::PLATFORM_HIERARCHY);
}

impl private::Sealed for Hierarchy {}

impl TpmResource for Hierarchy {
    // Not using Deref-mediated method coercion due to PolicyKind's use
    // of trait object references.  Implementing TpmResource directly is
    // more ergonomic in this case.
    fn tr(&self) -> esys_sys::ESYS_TR {
        self.0.tr()
    }
}
