#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

pub mod handle;
pub mod marshal;
pub mod types;

#[macro_use]
mod error;
mod private {
    pub trait Sealed {}
}

pub use error::{try_decode_rc, Error, Result};
pub use handle::{AuthSession, Handle, Hierarchy, TpmResource};
pub use marshal::{Marshal, Unmarshal};

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::ptr::{self, NonNull};

use esys_sys::ESYS_TR_NONE;

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
            &mut tcti
        ))?;

        let mut esys = ptr::null_mut();
        wrap_rc!(esys_sys::Esys_Initialize(&mut esys, tcti, ptr::null_mut()))?;

        Ok(Self(esys))
    }

    pub fn set_auth(&self, handle: &dyn TpmResource, auth: &types::sys::TPM2B_AUTH) -> Result<()> {
        wrap_rc!(esys_sys::Esys_TR_SetAuth(**self, handle.tr(), auth))
    }

    pub fn activate_credential(
        &self,
        credential_handle: &dyn TpmResource,
        credential_auth: Option<&AuthSession<'_>>,
        key_handle: &dyn TpmResource,
        key_auth: Option<&AuthSession<'_>>,
        blob: &types::sys::TPM2B_ID_OBJECT,
        secret: &types::sys::TPM2B_ENCRYPTED_SECRET,
    ) -> Result<EsysBox<types::sys::TPM2B_DIGEST>> {
        let credential_auth = credential_auth.map_or(ESYS_TR_NONE, TpmResource::tr);
        let key_auth = key_auth.map_or(ESYS_TR_NONE, TpmResource::tr);

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
            &mut out
        ))?;

        Ok(EsysBox(unsafe { NonNull::new_unchecked(out) }))
    }

    pub fn read_public(
        &self,
        handle: &dyn TpmResource,
    ) -> Result<EsysBox<types::sys::TPM2B_PUBLIC>> {
        let mut out = ptr::null_mut();

        wrap_rc!(esys_sys::Esys_ReadPublic(
            **self,
            handle.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut out,
            ptr::null_mut(),
            ptr::null_mut()
        ))?;

        Ok(EsysBox(unsafe { NonNull::new_unchecked(out) }))
    }

    pub fn create(
        &self,
        parent: &dyn TpmResource,
        auth: &AuthSession<'_>,
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
            &pcrs,
            &mut priv_out,
            &mut pub_out,
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
        parent: &dyn TpmResource,
        auth: &AuthSession<'_>,
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
            &mut out
        ))?;

        Ok(EsysBox(unsafe { NonNull::new_unchecked(out) }))
    }

    pub fn policy_digest(
        &self,
        auth_session: &AuthSession<'_>,
    ) -> Result<EsysBox<types::sys::TPM2B_DIGEST>> {
        let mut out = ptr::null_mut();

        wrap_rc!(esys_sys::Esys_PolicyGetDigest(
            **self,
            auth_session.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut out
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
        session_type: SessionType,
        sym: &types::sys::TPMT_SYM_DEF,
        auth_hash: types::sys::TPMI_ALG_HASH,
    ) -> Result<AuthSession<'_>> {
        let mut out = 0;

        wrap_rc!(esys_sys::Esys_StartAuthSession(
            **self,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ptr::null(),
            session_type.into_tpm_se(),
            sym,
            auth_hash,
            &mut out
        ))?;

        Ok(AuthSession(Handle::transient(out, self)))
    }

    pub fn load(
        &self,
        parent: &dyn TpmResource,
        auth: &AuthSession<'_>,
        private: &types::sys::TPM2B_PRIVATE,
        public: &types::sys::TPM2B_PUBLIC,
    ) -> Result<Handle<'_>> {
        let mut out = 0;

        wrap_rc!(esys_sys::Esys_Load(
            **self,
            parent.tr(),
            auth.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            private,
            public,
            &mut out
        ))?;

        Ok(Handle::transient(out, self))
    }

    pub fn create_primary(
        &self,
        auth: &AuthSession<'_>,
        hierarchy: Hierarchy,
        sensitive: &types::sys::TPM2B_SENSITIVE_CREATE,
        public: &types::sys::TPM2B_PUBLIC,
        data: Option<&types::sys::TPM2B_DATA>,
    ) -> Result<Handle<'_>> {
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
            &pcrs,
            &mut out,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut()
        ))?;

        Ok(Handle::transient(out, self))
    }

    pub fn from_tpm_public(
        &self,
        index: types::sys::TPM2_HANDLE,
        auth: Option<&AuthSession<'_>>,
    ) -> Result<Handle<'_>> {
        let mut out = 0;

        wrap_rc!(esys_sys::Esys_TR_FromTPMPublic(
            **self,
            index,
            auth.map_or(ESYS_TR_NONE, TpmResource::tr),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut out
        ))?;

        // SAFETY: Handles created by FromTPMPublic do not count as transient
        // handles.
        // NOTE: Technically, objects created from persistent resources on which
        // this function is used have a separate destruction flow through
        // Esys_TR_Close.  However, since we do not need to deal with
        // serialization of resource objects, it is fine to defer cleanup to the
        // final context flush.
        Ok(Handle::fixed(out))
    }

    // Instantiates a Handle that is dropped on exit
    #[allow(clippy::cast_possible_truncation)]
    pub fn hmac(
        &self,
        key: &dyn TpmResource,
        auth: &AuthSession<'_>,
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
                &payload,
                alg,
                &mut out
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
                &mut seq
            ))?;

            let seq = Handle::transient(seq, self);

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
                    &payload
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
                &payload,
                Hierarchy::NULL.tr(),
                &mut out,
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
        hierarchy: Hierarchy,
        object: Handle<'_>,
        auth: &AuthSession<'_>,
        persist: u32,
    ) -> Result<Option<Handle<'_>>> {
        let mut out = 0;

        wrap_rc!(esys_sys::Esys_EvictControl(
            **self,
            hierarchy.tr(),
            object.tr(),
            auth.tr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            persist,
            &mut out
        ))?;
        drop(object);

        Ok(if out == ESYS_TR_NONE {
            None
        } else {
            Some(Handle::fixed(out))
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
        if let Err(e) = wrap_rc!(esys_sys::Esys_GetTcti(**self, &mut tcti)) {
            log::error!("could not get inner TCTI context: {}", e);
        }

        unsafe {
            esys_sys::Esys_Finalize(&mut self.0);
            tcti_sys::Tss2_TctiLdr_Finalize(&mut tcti);
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

// NOTE: Only PolicySecret needed for now.
pub enum PolicyKind<'a> {
    Secret {
        handle: &'a dyn TpmResource,
        auth: &'a AuthSession<'a>,
    },
}

impl Policy<'_> {
    fn apply(self, session: &mut AuthSession<'_>) -> Result<()> {
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

#[derive(Clone, Copy, Debug)]
pub enum SessionType {
    HMAC,
    Policy,
    Trial,
}

impl SessionType {
    pub(crate) fn into_tpm_se(self) -> types::sys::TPM2_SE {
        match self {
            Self::HMAC => types::sys::DEF_TPM2_SE_HMAC,
            Self::Policy => types::sys::DEF_TPM2_SE_POLICY,
            Self::Trial => types::sys::DEF_TPM2_SE_TRIAL,
        }
    }
}

#[cfg(test)]
mod tests {}
