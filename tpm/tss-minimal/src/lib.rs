// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

pub mod handle;
pub mod marshal;
pub mod types;

mod error;
mod private {
    pub trait Sealed {}
}

pub use error::{Error, Result};
pub use handle::{EsysResource, Persistent, Transient};
pub use marshal::{Marshal, Unmarshal};

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::ptr::{self, NonNull};

use esys_sys::ESYS_TR_NONE;

use crate::error::wrap_rc;

#[derive(Debug)]
pub struct EsysContext(*mut esys_sys::ESYS_CONTEXT);

// SAFETY: ESYS_CONTEXT does not have thread affinity.
unsafe impl Send for EsysContext {}

// Methods that do not instantiate new Handles
impl EsysContext {
    pub fn new(tcti_conf: &CStr) -> Result<Self> {
        let mut tcti = ptr::null_mut();
        wrap_rc!(tcti_sys::Tss2_TctiLdr_Initialize(
            tcti_conf.as_ptr(),
            &raw mut tcti
        ))?;

        let mut esys = ptr::null_mut();
        wrap_rc!(esys_sys::Esys_Initialize(
            &raw mut esys,
            tcti,
            ptr::null_mut()
        ))?;

        Ok(Self(esys))
    }

    pub fn set_auth(&self, handle: &dyn EsysResource, auth: &types::sys::TPM2B_AUTH) -> Result<()> {
        wrap_rc!(esys_sys::Esys_TR_SetAuth(**self, handle.tr(), auth))
    }

    pub fn activate_credential(
        &self,
        credential_handle: &dyn EsysResource,
        credential_auth: Option<&dyn EsysResource>,
        key_handle: &dyn EsysResource,
        key_auth: Option<&dyn EsysResource>,
        blob: &types::sys::TPM2B_ID_OBJECT,
        secret: &types::sys::TPM2B_ENCRYPTED_SECRET,
    ) -> Result<EsysBox<types::sys::TPM2B_DIGEST>> {
        let credential_auth = credential_auth.map_or(ESYS_TR_NONE, EsysResource::tr);
        let key_auth = key_auth.map_or(ESYS_TR_NONE, EsysResource::tr);

        let mut out = ptr::null_mut();

        wrap_rc!(esys_sys::Esys_ActivateCredential(
            **self,
            credential_handle.tr(),
            key_handle.tr(),
            credential_auth,
            key_auth,
            ESYS_TR_NONE,
            blob,
            secret,
            &raw mut out
        ))?;

        Ok(EsysBox(unsafe { NonNull::new_unchecked(out) }))
    }

    pub fn read_public(
        &self,
        handle: &dyn EsysResource,
    ) -> Result<EsysBox<types::sys::TPM2B_PUBLIC>> {
        let mut out = ptr::null_mut();

        wrap_rc!(esys_sys::Esys_ReadPublic(
            **self,
            handle.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &raw mut out,
            ptr::null_mut(),
            ptr::null_mut()
        ))?;

        Ok(EsysBox(unsafe { NonNull::new_unchecked(out) }))
    }

    pub fn create(
        &self,
        parent: &dyn EsysResource,
        auth: &dyn EsysResource,
        sensitive: &types::sys::TPM2B_SENSITIVE_CREATE,
        public: &types::sys::TPM2B_PUBLIC,
        data: Option<&types::sys::TPM2B_DATA>,
    ) -> Result<(
        EsysBox<types::sys::TPM2B_PRIVATE>,
        EsysBox<types::sys::TPM2B_PUBLIC>,
    )> {
        let mut priv_out = ptr::null_mut();
        let mut pub_out = ptr::null_mut();
        let mut pcrs = MaybeUninit::<types::sys::TPML_PCR_SELECTION>::uninit();

        unsafe {
            ptr::addr_of_mut!((*pcrs.as_mut_ptr()).count).write(0);
        }

        let pcrs = unsafe { pcrs.assume_init() };

        wrap_rc!(esys_sys::Esys_Create(
            **self,
            parent.tr(),
            auth.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            sensitive,
            public,
            data.map_or_else(ptr::null, |x| x),
            &raw const pcrs,
            &raw mut priv_out,
            &raw mut pub_out,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut()
        ))?;

        Ok((
            EsysBox(unsafe { NonNull::new_unchecked(priv_out) }),
            EsysBox(unsafe { NonNull::new_unchecked(pub_out) }),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn import(
        &self,
        parent: &dyn EsysResource,
        auth: &dyn EsysResource,
        key: Option<&types::sys::TPM2B_DATA>,
        public: &types::sys::TPM2B_PUBLIC,
        dup: &types::sys::TPM2B_PRIVATE,
        seed: &types::sys::TPM2B_ENCRYPTED_SECRET,
        alg: &types::sys::TPMT_SYM_DEF_OBJECT,
    ) -> Result<EsysBox<types::sys::TPM2B_PRIVATE>> {
        let mut out = ptr::null_mut();

        wrap_rc!(esys_sys::Esys_Import(
            **self,
            parent.tr(),
            auth.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            key.map_or_else(ptr::null, |x| x),
            public,
            dup,
            seed,
            alg,
            &raw mut out
        ))?;

        Ok(EsysBox(unsafe { NonNull::new_unchecked(out) }))
    }

    pub fn policy_digest(
        &self,
        auth_session: &dyn EsysResource,
    ) -> Result<EsysBox<types::sys::TPM2B_DIGEST>> {
        let mut out = ptr::null_mut();

        wrap_rc!(esys_sys::Esys_PolicyGetDigest(
            **self,
            auth_session.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &raw mut out
        ))?;

        Ok(EsysBox(unsafe { NonNull::new_unchecked(out) }))
    }

    pub(crate) fn flush(&self, index: handle::ESYS_TR) -> Result<()> {
        wrap_rc!(esys_sys::Esys_FlushContext(**self, index))
    }
}

// Methods that instantiate Handles
impl EsysContext {
    pub fn start_auth_session(
        &self,
        session_type: types::sys::TPM2_SE,
        sym: &types::sys::TPMT_SYM_DEF,
        auth_hash: types::sys::TPMI_ALG_HASH,
    ) -> Result<Transient<'_>> {
        let mut out = 0;

        wrap_rc!(esys_sys::Esys_StartAuthSession(
            **self,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ptr::null(),
            session_type,
            sym,
            auth_hash,
            &raw mut out
        ))?;

        Ok(Transient::new(out, self))
    }

    pub fn load(
        &self,
        parent: &dyn EsysResource,
        auth: &dyn EsysResource,
        private: &types::sys::TPM2B_PRIVATE,
        public: &types::sys::TPM2B_PUBLIC,
    ) -> Result<Transient<'_>> {
        let mut out = 0;

        wrap_rc!(esys_sys::Esys_Load(
            **self,
            parent.tr(),
            auth.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            private,
            public,
            &raw mut out
        ))?;

        Ok(Transient::new(out, self))
    }

    pub fn create_primary(
        &self,
        auth: &dyn EsysResource,
        hierarchy: Persistent,
        sensitive: &types::sys::TPM2B_SENSITIVE_CREATE,
        public: &types::sys::TPM2B_PUBLIC,
        data: Option<&types::sys::TPM2B_DATA>,
    ) -> Result<Transient<'_>> {
        let mut out = 0;
        let mut pcrs = MaybeUninit::<types::sys::TPML_PCR_SELECTION>::uninit();

        unsafe {
            ptr::addr_of_mut!((*pcrs.as_mut_ptr()).count).write(0);
        }

        let pcrs = unsafe { pcrs.assume_init() };

        wrap_rc!(esys_sys::Esys_CreatePrimary(
            **self,
            hierarchy.tr(),
            auth.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            sensitive,
            public,
            data.map_or_else(ptr::null, |x| x),
            &raw const pcrs,
            &raw mut out,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut()
        ))?;

        Ok(Transient::new(out, self))
    }

    pub fn from_tpm_public(
        &self,
        index: types::sys::TPM2_HANDLE,
        auth: Option<&dyn EsysResource>,
    ) -> Result<Persistent> {
        let mut out = 0;

        wrap_rc!(esys_sys::Esys_TR_FromTPMPublic(
            **self,
            index,
            auth.map_or(ESYS_TR_NONE, EsysResource::tr),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &raw mut out
        ))?;

        // SAFETY: Handles created by FromTPMPublic do not count as transient
        // handles.
        // NOTE: Technically, objects created from persistent resources on which
        // this function is used have a separate destruction flow through
        // Esys_TR_Close.  However, since we do not need to deal with
        // serialization of resource objects, it is fine to defer cleanup to the
        // final context flush.
        Ok(Persistent::new(out))
    }

    // Instantiates a Handle that is dropped on exit
    #[allow(clippy::cast_possible_truncation)]
    pub fn hmac(
        &self,
        key: &dyn EsysResource,
        auth: &dyn EsysResource,
        alg: types::sys::TPM2_ALG_ID,
        mut buf: &[u8],
    ) -> Result<EsysBox<types::sys::TPM2B_DIGEST>> {
        const MAX_BUF: usize = types::sys::TPM2_MAX_DIGEST_BUFFER as usize;
        let mut out = ptr::null_mut();

        let mut payload = types::sys::TPM2B_MAX_BUFFER {
            size: 0,
            buffer: [0; MAX_BUF],
        };
        let mut seq = 0;

        if buf.len() <= MAX_BUF {
            payload.size = buf.len() as _;
            payload.buffer[..buf.len()].copy_from_slice(buf);

            wrap_rc!(esys_sys::Esys_HMAC(
                **self,
                key.tr(),
                auth.tr(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &raw const payload,
                alg,
                &raw mut out
            ))?;
        } else {
            wrap_rc!(esys_sys::Esys_HMAC_Start(
                **self,
                key.tr(),
                auth.tr(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ptr::null(),
                alg,
                &raw mut seq
            ))?;

            let seq = Transient::new(seq, self);

            while buf.len() > MAX_BUF {
                let chunk;
                (chunk, buf) = buf.split_at(MAX_BUF);
                payload.size = MAX_BUF as _;
                payload.buffer.copy_from_slice(chunk);

                wrap_rc!(esys_sys::Esys_SequenceUpdate(
                    **self,
                    seq.tr(),
                    auth.tr(),
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &raw const payload
                ))?;
            }

            payload.size = buf.len() as _;
            payload.buffer[..buf.len()].copy_from_slice(buf);
            wrap_rc!(esys_sys::Esys_SequenceComplete(
                **self,
                seq.tr(),
                auth.tr(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &raw const payload,
                Persistent::NULL_HIERARCHY.tr(),
                &raw mut out,
                ptr::null_mut()
            ))?;
            // SequenceComplete flushes the transient handle for seq, so we do
            // not need to run its drop code.
            std::mem::forget(seq);
        }

        Ok(EsysBox(unsafe { NonNull::new_unchecked(out) }))
    }

    pub fn evict(
        &self,
        hierarchy: Persistent,
        object: &dyn EsysResource,
        auth: &dyn EsysResource,
        persist: u32,
    ) -> Result<Option<Persistent>> {
        let mut out = 0;

        wrap_rc!(esys_sys::Esys_EvictControl(
            **self,
            hierarchy.tr(),
            object.tr(),
            auth.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            persist,
            &raw mut out
        ))?;

        Ok(if out == ESYS_TR_NONE {
            None
        } else {
            Some(Persistent::new(out))
        })
    }
}

impl Deref for EsysContext {
    type Target = *mut esys_sys::ESYS_CONTEXT;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for EsysContext {
    fn drop(&mut self) {
        let mut tcti = ptr::null_mut();
        if let Err(e) = wrap_rc!(esys_sys::Esys_GetTcti(**self, &raw mut tcti)) {
            log::error!("could not get inner TCTI context: {e}");
        }

        unsafe {
            esys_sys::Esys_Finalize(&raw mut self.0);
            tcti_sys::Tss2_TctiLdr_Finalize(&raw mut tcti);
        };
    }
}

#[derive(Debug)]
pub struct EsysBox<T>(NonNull<T>);

impl<T> Deref for EsysBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.0.as_ref() }
    }
}

impl<T> DerefMut for EsysBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.0.as_mut() }
    }
}

impl<T> Drop for EsysBox<T> {
    fn drop(&mut self) {
        unsafe { esys_sys::Esys_Free(self.0.as_ptr().cast()) };
    }
}

pub struct Policy<'a> {
    kind: PolicyKind<'a>,
    context: &'a EsysContext,
}

impl<'a> Policy<'a> {
    #[must_use]
    pub fn new(kind: PolicyKind<'a>, context: &'a EsysContext) -> Self {
        Self { kind, context }
    }
}

// NOTE: Only PolicySecret needed for now
pub enum PolicyKind<'a> {
    Secret {
        handle: &'a dyn EsysResource,
        auth: &'a dyn EsysResource,
    },
}

impl Policy<'_> {
    pub fn apply(self, session: &mut dyn EsysResource) -> Result<()> {
        match self.kind {
            PolicyKind::Secret { handle, auth } => {
                wrap_rc!(esys_sys::Esys_PolicySecret(
                    **self.context,
                    handle.tr(),
                    session.tr(),
                    auth.tr(),
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut()
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {}
