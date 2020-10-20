// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
    /// Used to memoize [`Context`]s to PKCS#11 libraries.
    ///
    /// The PKCS#11 spec allows implementations to reject multiple successive calls to C_Initialize by returning CKR_CRYPTOKI_ALREADY_INITIALIZED.
    /// We can't just ignore the error and create a Context anyway (*), because each Context's Drop impl will call C_Finalize
    /// and we'll have the equivalent of a double-free.
    ///
    /// But we don't want users to keep track of this, so we memoize Contexts based on the library path and returns the same Context for
    /// multiple requests to load the same library.
    ///
    /// However if the memoizing map were to hold a strong reference to the Context, then the Context would never be released even after the user dropped theirs,
    /// so we need the map to specifically hold a weak reference instead.
    ///
    /// (*): libp11 *does* actually do this, by ignoring CKR_CRYPTOKI_ALREADY_INITIALIZED and treating it as success.
    ///      It can do this because it never calls C_Finalize anyway and leaves it to the user.
    static ref CONTEXTS: std::sync::Mutex<std::collections::BTreeMap<std::path::PathBuf, std::sync::Weak<Context>>> = Default::default();
}

/// A context to a PKCS#11 library.
pub struct Context {
    sessions: std::sync::Mutex<
        std::collections::BTreeMap<pkcs11_sys::CK_SLOT_ID, std::sync::Weak<crate::Session>>,
    >,

    // Ensure this comes after anything else that might be using the library, like `sessions` above, so that it's dropped after them.
    _library: crate::dl::Library,

    pub(crate) C_CloseSession: pkcs11_sys::CK_C_CloseSession,
    pub(crate) C_DestroyObject: pkcs11_sys::CK_C_DestroyObject,
    pub(crate) C_Encrypt: pkcs11_sys::CK_C_Encrypt,
    pub(crate) C_EncryptInit: pkcs11_sys::CK_C_EncryptInit,
    C_Finalize: Option<pkcs11_sys::CK_C_Finalize>,
    pub(crate) C_FindObjects: pkcs11_sys::CK_C_FindObjects,
    pub(crate) C_FindObjectsFinal: pkcs11_sys::CK_C_FindObjectsFinal,
    pub(crate) C_FindObjectsInit: pkcs11_sys::CK_C_FindObjectsInit,
    pub(crate) C_GenerateKeyPair: pkcs11_sys::CK_C_GenerateKeyPair,
    pub(crate) C_GetAttributeValue: pkcs11_sys::CK_C_GetAttributeValue,
    pub(crate) C_GetSessionInfo: pkcs11_sys::CK_C_GetSessionInfo,
    C_GetSlotList: pkcs11_sys::CK_C_GetSlotList,
    C_GetTokenInfo: pkcs11_sys::CK_C_GetTokenInfo,
    C_GetInfo: Option<pkcs11_sys::CK_C_GetInfo>,
    pub(crate) C_Login: pkcs11_sys::CK_C_Login,
    C_OpenSession: pkcs11_sys::CK_C_OpenSession,
    pub(crate) C_Sign: pkcs11_sys::CK_C_Sign,
    pub(crate) C_SignInit: pkcs11_sys::CK_C_SignInit,
}

impl Context {
    /// Load the PKCS#11 library at the specified path and create a context.
    pub fn load(lib_path: std::path::PathBuf) -> Result<std::sync::Arc<Self>, LoadContextError> {
        Ok(weak_cache_get_or_insert(&CONTEXTS, lib_path, |lib_path| {
            Ok(Context::load_inner(lib_path)?)
        })?)
    }

    fn load_inner(lib_path: &std::path::Path) -> Result<Self, LoadContextError> {
        unsafe {
            let library =
                crate::dl::Library::load(lib_path).map_err(LoadContextError::LoadLibrary)?;

            let C_GetFunctionList: pkcs11_sys::CK_C_GetFunctionList = *library
                .symbol(std::ffi::CStr::from_bytes_with_nul(b"C_GetFunctionList\0").unwrap())
                .map_err(LoadContextError::LoadGetFunctionListSymbol)?;

            let mut function_list = std::ptr::null();
            let result = C_GetFunctionList(&mut function_list);
            if result != pkcs11_sys::CKR_OK {
                return Err(LoadContextError::GetFunctionListFailed(
                    format!("C_GetFunctionList failed with {}", result).into(),
                ));
            }
            if function_list.is_null() {
                return Err(LoadContextError::GetFunctionListFailed(
                    "C_GetFunctionList succeeded but function list is still NULL".into(),
                ));
            }
            let version = (*function_list).version;
            if version.major != 2 || version.minor < 1 {
                // We require 2.20 or higher. However opensc-pkcs11spy self-reports as v2.11 in the initial CK_FUNCTION_LIST version,
                // and at least one smartcard vendor's library self-reports as v2.01 in the initial CK_FUNCTION_LIST version.
                // Both of these report the real version in the C_GetInfo call (in opensc-pkcs11spy's case, it forwards C_GetInfo to
                // the underlying PKCS#11 library), so we check the result of that later.
                //
                // So the check here is a more lax v2.01 check.
                return Err(LoadContextError::UnsupportedPkcs11Version {
                    expected: pkcs11_sys::CK_VERSION { major: 2, minor: 1 },
                    actual: version,
                });
            }

            let C_CloseSession = (*function_list)
                .C_CloseSession
                .ok_or(LoadContextError::MissingFunction("C_CloseSession"))?;
            let C_DestroyObject = (*function_list)
                .C_DestroyObject
                .ok_or(LoadContextError::MissingFunction("C_DestroyObject"))?;
            let C_Encrypt = (*function_list)
                .C_Encrypt
                .ok_or(LoadContextError::MissingFunction("C_Encrypt"))?;
            let C_EncryptInit = (*function_list)
                .C_EncryptInit
                .ok_or(LoadContextError::MissingFunction("C_EncryptInit"))?;
            let C_Finalize = (*function_list).C_Finalize;
            let C_FindObjects = (*function_list)
                .C_FindObjects
                .ok_or(LoadContextError::MissingFunction("C_FindObjects"))?;
            let C_FindObjectsFinal = (*function_list)
                .C_FindObjectsFinal
                .ok_or(LoadContextError::MissingFunction("C_FindObjectsFinal"))?;
            let C_FindObjectsInit = (*function_list)
                .C_FindObjectsInit
                .ok_or(LoadContextError::MissingFunction("C_FindObjectsInit"))?;
            let C_GenerateKeyPair = (*function_list)
                .C_GenerateKeyPair
                .ok_or(LoadContextError::MissingFunction("C_GenerateKeyPair"))?;
            let C_GetAttributeValue = (*function_list)
                .C_GetAttributeValue
                .ok_or(LoadContextError::MissingFunction("C_GetAttributeValue"))?;
            let C_GetInfo = (*function_list).C_GetInfo;
            let C_GetSessionInfo = (*function_list)
                .C_GetSessionInfo
                .ok_or(LoadContextError::MissingFunction("C_GetSessionInfo"))?;
            let C_GetSlotList = (*function_list)
                .C_GetSlotList
                .ok_or(LoadContextError::MissingFunction("C_GetSlotList"))?;
            let C_GetTokenInfo = (*function_list)
                .C_GetTokenInfo
                .ok_or(LoadContextError::MissingFunction("C_GetTokenInfo"))?;
            let C_Login = (*function_list)
                .C_Login
                .ok_or(LoadContextError::MissingFunction("C_Login"))?;
            let C_OpenSession = (*function_list)
                .C_OpenSession
                .ok_or(LoadContextError::MissingFunction("C_OpenSession"))?;
            let C_Sign = (*function_list)
                .C_Sign
                .ok_or(LoadContextError::MissingFunction("C_Sign"))?;
            let C_SignInit = (*function_list)
                .C_SignInit
                .ok_or(LoadContextError::MissingFunction("C_SignInit"))?;

            // Do initialization as the very last thing, so that if it succeeds we're guaranteed to call the corresponding C_Finalize
            let C_Initialize = (*function_list)
                .C_Initialize
                .ok_or(LoadContextError::MissingFunction("C_Initialize"))?;
            let initialize_args = pkcs11_sys::CK_C_INITIALIZE_ARGS {
                CreateMutex: create_mutex,
                DestroyMutex: destroy_mutex,
                LockMutex: lock_mutex,
                UnlockMutex: unlock_mutex,
                flags: pkcs11_sys::CKF_LIBRARY_CANT_CREATE_OS_THREADS,
                pReserved: std::ptr::null_mut(),
            };
            let result = C_Initialize(&initialize_args);
            if result != pkcs11_sys::CKR_OK {
                return Err(LoadContextError::InitializeFailed(result));
            }

            let context = Context {
                sessions: Default::default(),

                _library: library,

                C_CloseSession,
                C_DestroyObject,
                C_Encrypt,
                C_EncryptInit,
                C_Finalize,
                C_FindObjects,
                C_FindObjectsFinal,
                C_FindObjectsInit,
                C_GenerateKeyPair,
                C_GetAttributeValue,
                C_GetInfo,
                C_GetSessionInfo,
                C_GetSlotList,
                C_GetTokenInfo,
                C_Login,
                C_OpenSession,
                C_Sign,
                C_SignInit,
            };

            let version = context.info().map_or(
                version, // Doesn't support C_GetInfo, so the initial version in the CK_FUNCTION_LIST is all we have.
                |info| info.cryptokiVersion,
            );
            if version.major != 2 || version.minor < 20 {
                return Err(LoadContextError::UnsupportedPkcs11Version {
                    expected: pkcs11_sys::CK_VERSION {
                        major: 2,
                        minor: 20,
                    },
                    actual: version,
                });
            }

            Ok(context)
        }
    }
}

/// An error from loading a PKCS#11 library and creating a context.
#[derive(Debug)]
pub enum LoadContextError {
    LoadGetFunctionListSymbol(String),
    LoadLibrary(String),
    GetFunctionListFailed(std::borrow::Cow<'static, str>),
    InitializeFailed(pkcs11_sys::CK_RV),
    MissingFunction(&'static str),
    UnsupportedPkcs11Version {
        expected: pkcs11_sys::CK_VERSION,
        actual: pkcs11_sys::CK_VERSION,
    },
}

impl std::fmt::Display for LoadContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadContextError::LoadGetFunctionListSymbol(message) => {
                write!(f, "could not load C_GetFunctionList symbol: {}", message)
            }
            LoadContextError::LoadLibrary(message) => {
                write!(f, "could not load library: {}", message)
            }
            LoadContextError::GetFunctionListFailed(message) => {
                write!(f, "could not get function list: {}", message)
            }
            LoadContextError::InitializeFailed(result) => {
                write!(f, "C_Initialize failed with {}", result)
            }
            LoadContextError::MissingFunction(name) => {
                write!(f, "function list is missing required function {}", name)
            }
            LoadContextError::UnsupportedPkcs11Version { expected, actual } => write!(
                f,
                "expected library to support {} or higher, but it supports {}",
                expected, actual
            ),
        }
    }
}

impl std::error::Error for LoadContextError {}

impl Context {
    /// Get the library's information.
    ///
    /// If the library does not support getting its information, this returns `None`.
    pub fn info(&self) -> Option<pkcs11_sys::CK_INFO> {
        unsafe {
            if let Some(C_GetInfo) = self.C_GetInfo {
                let mut info = std::mem::MaybeUninit::uninit();

                let result = C_GetInfo(info.as_mut_ptr());
                if result != pkcs11_sys::CKR_OK {
                    return None;
                }

                let info = info.assume_init();
                Some(info)
            } else {
                None
            }
        }
    }
}

impl Context {
    /// Get an iterator of slots managed by this library.
    #[allow(clippy::needless_lifetimes)]
    pub fn slots(&self) -> Result<impl Iterator<Item = pkcs11_sys::CK_SLOT_ID>, ListSlotsError> {
        // The spec for C_GetSlotList says that it can be used in two ways to get the number of slots:
        //
        // - If the buffer is NULL, `*pulCount` is set to the number of slots, and the call returns `CKR_OK`
        // - If the buffer is not NULL but is too small, `*pulCount` is set to the number of slots, and the call returns `CKR_BUFFER_TOO_SMALL`
        //
        // Since we always have to handle the second case (in case a slot is created between the call with NULL and the call with the actual buffer),
        // we can write a working implementation without needing the first case at all.

        unsafe {
            let mut slot_ids = vec![];

            loop {
                let mut actual_len =
                    std::convert::TryInto::try_into(slot_ids.len()).expect("usize -> CK_ULONG");
                let result = (self.C_GetSlotList)(
                    pkcs11_sys::CK_TRUE,
                    slot_ids.as_mut_ptr(),
                    &mut actual_len,
                );
                match result {
                    pkcs11_sys::CKR_OK => {
                        let actual_len =
                            std::convert::TryInto::try_into(actual_len).expect("CK_ULONG -> usize");

                        // If slot_ids.len() < actual_len, then the PKCS#11 library has scribbled past the end of the buffer.
                        // This is not safe to recover from.
                        //
                        // Vec::truncate silently ignores a request to truncate to longer than its current length,
                        // so we must check for it ourselves.
                        assert!(slot_ids.len() >= actual_len);

                        slot_ids.truncate(actual_len);

                        return Ok(slot_ids.into_iter());
                    }

                    pkcs11_sys::CKR_BUFFER_TOO_SMALL => {
                        let actual_len =
                            std::convert::TryInto::try_into(actual_len).expect("CK_ULONG -> usize");

                        slot_ids.resize_with(actual_len, Default::default);

                        continue;
                    }

                    result => return Err(ListSlotsError::GetSlotList(result)),
                }
            }
        }
    }
}

/// An error from listing all slots managed by this library.
#[derive(Debug)]
pub enum ListSlotsError {
    GetSlotList(pkcs11_sys::CK_RV),
}

impl std::fmt::Display for ListSlotsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListSlotsError::GetSlotList(result) => {
                write!(f, "C_GetSlotList failed with {}", result)
            }
        }
    }
}

impl std::error::Error for ListSlotsError {}

impl Context {
    /// Finds a slot that matches the criteria set by the given identifier.
    pub fn find_slot(
        &self,
        identifier: &crate::UriSlotIdentifier,
    ) -> Result<pkcs11_sys::CK_SLOT_ID, FindSlotError> {
        match identifier {
            crate::UriSlotIdentifier::Label(label) => {
                let mut slot = None;
                for context_slot in self.slots().map_err(FindSlotError::ListSlots)? {
                    let token_info = self
                        .token_info(context_slot)
                        .map_err(FindSlotError::GetTokenInfo)?;
                    if !token_info.flags.has(pkcs11_sys::CKF_TOKEN_INITIALIZED) {
                        continue;
                    }

                    let slot_label = String::from_utf8_lossy(&token_info.label);
                    // Labels are always 32 bytes, so shorter labels are padded with trailing whitespace which the URI parameter will not have.
                    let slot_label = slot_label.trim();
                    if slot_label != label {
                        continue;
                    }

                    slot = Some(context_slot);
                    break;
                }

                Ok(slot.ok_or(FindSlotError::NoMatchingSlotFound)?)
            }

            crate::UriSlotIdentifier::SlotId(slot_id) => Ok(*slot_id),
        }
    }
}

/// An error from finding a slot from its identifier.
#[derive(Debug)]
pub enum FindSlotError {
    GetTokenInfo(crate::GetTokenInfoError),
    ListSlots(ListSlotsError),
    NoMatchingSlotFound,
}

impl std::fmt::Display for FindSlotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindSlotError::GetTokenInfo(_) => f.write_str("could not get token info"),
            FindSlotError::ListSlots(_) => f.write_str("could not list slots"),
            FindSlotError::NoMatchingSlotFound => {
                f.write_str("could not find a slot with a matching label")
            }
        }
    }
}

impl std::error::Error for FindSlotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FindSlotError::GetTokenInfo(inner) => Some(inner),
            FindSlotError::ListSlots(inner) => Some(inner),
            FindSlotError::NoMatchingSlotFound => None,
        }
    }
}

impl Context {
    /// Get the info of the token in this slot.
    pub fn token_info(
        &self,
        slot_id: pkcs11_sys::CK_SLOT_ID,
    ) -> Result<pkcs11_sys::CK_TOKEN_INFO, GetTokenInfoError> {
        unsafe {
            let mut info = std::mem::MaybeUninit::uninit();

            let result = (self.C_GetTokenInfo)(slot_id, info.as_mut_ptr());
            if result != pkcs11_sys::CKR_OK {
                return Err(GetTokenInfoError::GetTokenInfo(result));
            }

            let info = info.assume_init();
            Ok(info)
        }
    }
}

/// An error from getting a token's info.
#[derive(Debug)]
pub enum GetTokenInfoError {
    GetTokenInfo(pkcs11_sys::CK_RV),
}

impl std::fmt::Display for GetTokenInfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetTokenInfoError::GetTokenInfo(result) => {
                write!(f, "C_GetTokenInfo failed with {}", result)
            }
        }
    }
}

impl std::error::Error for GetTokenInfoError {}

impl Context {
    /// Open a read-write session against the token in this slot.
    ///
    /// # Notes
    ///
    /// This API returns an existing open session for the specified slot ID if one exists elsewhere in the application.
    /// This is done to minimize the number of sessions open against the same slot. The PIN is ignored if
    /// an existing session is returned.
    ///
    /// Even though this API always opens a read-write session, the PIN is still optional. This is so that
    /// you don't need to specify the PIN if you're only going to perform such operations that don't require logging in.
    ///
    /// As a consequence of the above two points, if a PIN was not supplied the first time a session was requested for this slot,
    /// it will be in the R/W Public Session state and will never be able to transition to the R/W User Functions state.
    /// If you need the session to be in the R/W User Functions state, either first close all other sessions for this slot and
    /// then open a new one with the PIN, or make sure to always supply a PIN for any sessions opened against this slot.
    pub fn open_session(
        self: std::sync::Arc<Self>,
        slot_id: pkcs11_sys::CK_SLOT_ID,
        pin: Option<String>,
    ) -> Result<std::sync::Arc<crate::Session>, OpenSessionError> {
        let this = self.clone();

        Ok(weak_cache_get_or_insert(
            &self.sessions,
            slot_id,
            |slot_id| Ok(this.open_session_inner(*slot_id, pin)?),
        )?)
    }

    fn open_session_inner(
        self: std::sync::Arc<Self>,
        slot_id: pkcs11_sys::CK_SLOT_ID,
        pin: Option<String>,
    ) -> Result<crate::Session, OpenSessionError> {
        unsafe {
            let mut handle = pkcs11_sys::CK_INVALID_SESSION_HANDLE;
            let result = (self.C_OpenSession)(
                slot_id,
                pkcs11_sys::CKF_SERIAL_SESSION | pkcs11_sys::CKF_RW_SESSION,
                std::ptr::null_mut(),
                None,
                &mut handle,
            );
            if result != pkcs11_sys::CKR_OK {
                return Err(OpenSessionError::OpenSessionFailed(
                    format!("C_OpenSession failed with {}", result).into(),
                ));
            }
            if handle == pkcs11_sys::CK_INVALID_SESSION_HANDLE {
                return Err(OpenSessionError::OpenSessionFailed(
                    "C_OpenSession succeeded but session handle is still CK_INVALID_HANDLE".into(),
                ));
            }
            let session = crate::Session::new(self, handle, pin);

            Ok(session)
        }
    }
}

/// An error from opening a session against a slot.
#[derive(Debug)]
pub enum OpenSessionError {
    OpenSessionFailed(std::borrow::Cow<'static, str>),
}

impl std::fmt::Display for OpenSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenSessionError::OpenSessionFailed(message) => {
                write!(f, "could not open session: {}", message)
            }
        }
    }
}

impl std::error::Error for OpenSessionError {}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            if let Some(C_Finalize) = self.C_Finalize {
                let _ = C_Finalize(std::ptr::null_mut());
            }
        }
    }
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

/// A PKCS#11 mutex implementation using a [`std::sync::Mutex`]
#[repr(C)]
struct Mutex {
    inner: std::sync::Mutex<()>,
    guard: Option<std::sync::MutexGuard<'static, ()>>,
}

unsafe extern "C" fn create_mutex(ppMutex: pkcs11_sys::CK_VOID_PTR_PTR) -> pkcs11_sys::CK_RV {
    let mutex = Mutex {
        inner: Default::default(),
        guard: None,
    };
    let mutex = Box::new(mutex);
    let mutex = Box::into_raw(mutex);
    *ppMutex = mutex as _;
    pkcs11_sys::CKR_OK
}

unsafe extern "C" fn destroy_mutex(pMutex: pkcs11_sys::CK_VOID_PTR) -> pkcs11_sys::CK_RV {
    if pMutex.is_null() {
        return pkcs11_sys::CKR_MUTEX_BAD;
    }

    let mut mutex: Box<Mutex> = Box::from_raw(pMutex as _);
    drop(mutex.guard.take());
    drop(mutex);
    pkcs11_sys::CKR_OK
}

unsafe extern "C" fn lock_mutex(pMutex: pkcs11_sys::CK_VOID_PTR) -> pkcs11_sys::CK_RV {
    if pMutex.is_null() {
        return pkcs11_sys::CKR_MUTEX_BAD;
    }

    let mutex: &mut Mutex = &mut *(pMutex as *mut _);
    let guard = match mutex.inner.lock() {
        Ok(guard) => guard,
        Err(_) => return pkcs11_sys::CKR_GENERAL_ERROR,
    };
    let guard = std::mem::transmute(guard);
    mutex.guard = guard;
    pkcs11_sys::CKR_OK
}

unsafe extern "C" fn unlock_mutex(pMutex: pkcs11_sys::CK_VOID_PTR) -> pkcs11_sys::CK_RV {
    if pMutex.is_null() {
        return pkcs11_sys::CKR_MUTEX_BAD;
    }

    let mutex: &mut Mutex = &mut *(pMutex as *mut _);
    if mutex.guard.take().is_none() {
        return pkcs11_sys::CKR_MUTEX_NOT_LOCKED;
    }
    pkcs11_sys::CKR_OK
}

fn weak_cache_get_or_insert<K, V, F, E>(
    cache: &std::sync::Mutex<std::collections::BTreeMap<K, std::sync::Weak<V>>>,
    key: K,
    value: F,
) -> Result<std::sync::Arc<V>, E>
where
    K: std::cmp::Ord,
    F: FnOnce(&K) -> Result<V, E>,
{
    match cache.lock().unwrap().entry(key) {
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let weak = entry.get();
            if let Some(strong) = weak.upgrade() {
                // Created this value before, and someone still has a strong reference to it, so we were able to upgrade our weak reference
                // to a new strong reference. Return this new strong reference.
                Ok(strong)
            } else {
                // Created this value before, but all the strong references to it have been dropped since then.
                // So treat this the same as if we'd never loaded this context before (the Vacant arm below).
                let value = value(entry.key())?;
                let strong = std::sync::Arc::new(value);
                let weak = std::sync::Arc::downgrade(&strong);
                let _ = entry.insert(weak);
                Ok(strong)
            }
        }

        std::collections::btree_map::Entry::Vacant(entry) => {
            // Never tried to create this value before. Load it, store the weak reference, and return the strong reference.
            let value = value(entry.key())?;
            let strong = std::sync::Arc::new(value);
            let weak = std::sync::Arc::downgrade(&strong);
            let _ = entry.insert(weak);
            Ok(strong)
        }
    }
}
