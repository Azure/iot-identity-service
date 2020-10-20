// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    non_camel_case_types,
    non_snake_case,
    clippy::must_use_candidate,
    clippy::use_self
)]

//! Refs:
//!
//! - <https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html>
//! - <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html>
//! - <https://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/pkcs11-ug-v2.40.html>
//!
//!
//! Headers:
//!
//! - <https://www.cryptsoft.com/pkcs11doc/STANDARD/include/v211/pkcs11t.h>
//! - <https://www.cryptsoft.com/pkcs11doc/STANDARD/include/v220/pkcs11t.h>
//! - <https://www.cryptsoft.com/pkcs11doc/STANDARD/include/v230/pkcs11t.h>
//! - <https://www.cryptsoft.com/pkcs11doc/STANDARD/include/v240/pkcs11t.h>

// Note: Section 2.1 "Structure packing" of the base spec says that all structs must be packed to 1 byte.
// In reality, this is only true of PKCS#11 libraries on Windows (which we don't support).
// For Linux, every PKCS#11 library tends to use no packing.
//
// See https://github.com/opendnssec/SoftHSMv2/issues/471 for some relevant discussion (not specific to softhsm).

macro_rules! define_enum {
	(@inner $type:ident $f:ident ( $($consts:tt)* ) ( $($match_arms:tt)* ) ()) => {
		#[derive(Clone, Copy, Debug, Eq, PartialEq)]
		#[repr(transparent)]
		pub struct $type(CK_ULONG);

		$($consts)*

		impl std::fmt::Display for $type {
			fn fmt(&self, $f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				match *self {
					$($match_arms)*
					$type(other) => write!($f, "0x{:08x}", other),
				}
			}
		}
	};

	(@inner $type:ident $f:ident ( $($consts:tt)* ) ( $($match_arms:tt)* ) ( $ident:ident = $value:expr, $($rest:tt)* )) => {
		define_enum! {
			@inner
			$type
			$f
			( $($consts)* pub const $ident: $type = $type($value); )
			( $($match_arms)* $ident => $f.write_str(stringify!($ident)), )
			( $($rest)* )
		}
	};

	($type:ident { $($tt:tt)* }) => {
		define_enum! {
			@inner
			$type
			f
			( )
			( )
			( $($tt)* )
		}
	};
}

// CK_ATTRIBUTE

#[derive(Debug)]
#[repr(C)]
pub struct CK_ATTRIBUTE {
    pub r#type: CK_ATTRIBUTE_TYPE,
    pub pValue: CK_VOID_PTR,
    pub ulValueLen: CK_ULONG,
}

#[derive(Debug)]
#[repr(C)]
pub struct CK_ATTRIBUTE_IN {
    pub r#type: CK_ATTRIBUTE_TYPE,
    pub pValue: CK_VOID_PTR_CONST,
    pub ulValueLen: CK_ULONG,
}

pub type CK_ATTRIBUTE_PTR = *mut CK_ATTRIBUTE;
pub type CK_ATTRIBUTE_PTR_CONST = *const CK_ATTRIBUTE_IN;

// CK_ATTRIBUTE_TYPE

define_enum!(CK_ATTRIBUTE_TYPE {
    CKA_CLASS = 0x0000_0000,
    CKA_DECRYPT = 0x0000_0105,
    CKA_EC_PARAMS = 0x0000_0180,
    CKA_EC_POINT = 0x0000_0181,
    CKA_ENCRYPT = 0x0000_0104,
    CKA_KEY_TYPE = 0x0000_0100,
    CKA_LABEL = 0x0000_0003,
    CKA_MODULUS = 0x0000_0120,
    CKA_MODULUS_BITS = 0x0000_0121,
    CKA_PRIVATE = 0x0000_0002,
    CKA_PUBLIC_EXPONENT = 0x0000_0122,
    CKA_SENSITIVE = 0x0000_0103,
    CKA_SIGN = 0x0000_0108,
    CKA_TOKEN = 0x0000_0001,
    CKA_VERIFY = 0x0000_010a,
});

// CK_BBOOL

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct CK_BBOOL(u8);

pub const CK_FALSE: CK_BBOOL = CK_BBOOL(0);
pub const CK_TRUE: CK_BBOOL = CK_BBOOL(1);

// CK_BYTE

pub type CK_BYTE = u8;

pub type CK_BYTE_PTR = *mut CK_BYTE;
pub type CK_BYTE_PTR_CONST = *const CK_BYTE;

// CK_CHAR

pub type CK_CHAR = CK_BYTE;

// CK_FLAGS

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct CK_INITIALIZE_FLAGS(CK_ULONG);

pub const CKF_LIBRARY_CANT_CREATE_OS_THREADS: CK_INITIALIZE_FLAGS =
    CK_INITIALIZE_FLAGS(0x0000_0001);

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct CK_OPEN_SESSION_FLAGS(CK_ULONG);

impl std::ops::BitOr<Self> for CK_OPEN_SESSION_FLAGS {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        CK_OPEN_SESSION_FLAGS(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CK_OPEN_SESSION_FLAGS {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

pub const CKF_RW_SESSION: CK_OPEN_SESSION_FLAGS = CK_OPEN_SESSION_FLAGS(0x0000_0002);
pub const CKF_SERIAL_SESSION: CK_OPEN_SESSION_FLAGS = CK_OPEN_SESSION_FLAGS(0x0000_0004);

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct CK_TOKEN_INFO_FLAGS(CK_ULONG);

impl CK_TOKEN_INFO_FLAGS {
    pub fn has(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

pub const CKF_TOKEN_INITIALIZED: CK_TOKEN_INFO_FLAGS = CK_TOKEN_INFO_FLAGS(0x0000_0400);

// CK_FUNCTION_LIST

#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,

    pub C_Initialize: Option<CK_C_Initialize>,
    pub C_Finalize: Option<CK_C_Finalize>,
    pub C_GetInfo: Option<CK_C_GetInfo>,

    _unused1: [Option<unsafe extern "C" fn()>; 1],

    pub C_GetSlotList: Option<CK_C_GetSlotList>,

    _unused2: [Option<unsafe extern "C" fn()>; 1],

    pub C_GetTokenInfo: Option<CK_C_GetTokenInfo>,

    _unused3: [Option<unsafe extern "C" fn()>; 5],

    pub C_OpenSession: Option<CK_C_OpenSession>,
    pub C_CloseSession: Option<CK_C_CloseSession>,

    _unused4: [Option<unsafe extern "C" fn()>; 1],

    pub C_GetSessionInfo: Option<CK_C_GetSessionInfo>,

    _unused5: [Option<unsafe extern "C" fn()>; 2],

    pub C_Login: Option<CK_C_Login>,

    _unused6: [Option<unsafe extern "C" fn()>; 3],

    pub C_DestroyObject: Option<CK_C_DestroyObject>,

    _unused7: [Option<unsafe extern "C" fn()>; 1],

    pub C_GetAttributeValue: Option<CK_C_GetAttributeValue>,

    _unused8: [Option<unsafe extern "C" fn()>; 1],

    pub C_FindObjectsInit: Option<CK_C_FindObjectsInit>,
    pub C_FindObjects: Option<CK_C_FindObjects>,
    pub C_FindObjectsFinal: Option<CK_C_FindObjectsFinal>,
    pub C_EncryptInit: Option<CK_C_EncryptInit>,
    pub C_Encrypt: Option<CK_C_Encrypt>,

    _unused9: [Option<unsafe extern "C" fn()>; 11],

    pub C_SignInit: Option<CK_C_SignInit>,
    pub C_Sign: Option<CK_C_Sign>,

    _unused10: [Option<unsafe extern "C" fn()>; 15],

    pub C_GenerateKeyPair: Option<CK_C_GenerateKeyPair>,

    _unused11: [Option<unsafe extern "C" fn()>; 8],
}

pub type CK_FUNCTION_LIST_PTR_CONST = *const CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_PTR_PTR = *mut CK_FUNCTION_LIST_PTR_CONST;

// CK_INFO

#[derive(Debug)]
#[repr(C)]
pub struct CK_INFO {
    pub cryptokiVersion: CK_VERSION,
    pub manufacturerID: [CK_UTF8CHAR; 32],
    pub flags: CK_ULONG,
    pub libraryDescription: [CK_UTF8CHAR; 32],
    pub libraryVersion: CK_VERSION,
}

pub type CK_INFO_PTR = *mut CK_INFO;

impl std::fmt::Display for CK_INFO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
			f,
			"description: [{}], version: [{}], manufacturer ID: [{}], PKCS#11 version: [{}], flags: [{}]",
			String::from_utf8_lossy(&self.libraryDescription).trim(),
			self.libraryVersion,
			String::from_utf8_lossy(&self.manufacturerID).trim(),
			self.cryptokiVersion,
			self.flags,
		)?;
        Ok(())
    }
}

// CK_C_INITIALIZE_ARGS

#[derive(Debug)]
#[repr(C)]
pub struct CK_C_INITIALIZE_ARGS {
    pub CreateMutex: CK_CREATEMUTEX,
    pub DestroyMutex: CK_DESTROYMUTEX,
    pub LockMutex: CK_LOCKMUTEX,
    pub UnlockMutex: CK_UNLOCKMUTEX,
    pub flags: CK_INITIALIZE_FLAGS,
    pub pReserved: CK_VOID_PTR,
}

pub type CK_C_INITIALIZE_ARGS_PTR = *const CK_C_INITIALIZE_ARGS;

// CK_KEY_TYPE

define_enum!(CK_KEY_TYPE {
    CKK_EC = 0x0000_0003,
    CKK_RSA = 0x0000_0000,
});

// CK_MECHANISM

#[derive(Debug)]
#[repr(C)]
pub struct CK_MECHANISM_IN {
    pub mechanism: CK_MECHANISM_TYPE,
    pub pParameter: CK_VOID_PTR_CONST,
    pub ulParameterLen: CK_ULONG,
}

pub type CK_MECHANISM_PTR_CONST = *const CK_MECHANISM_IN;

// CK_MECHANISM_TYPE

define_enum!(CK_MECHANISM_TYPE {
    CKM_EC_KEY_PAIR_GEN = 0x0000_1040,
    CKM_ECDSA = 0x0000_1041,
    CKM_RSA_PKCS = 0x0000_0001,
    CKM_RSA_X509 = 0x0000_0003,
    CKM_RSA_PKCS_KEY_PAIR_GEN = 0x0000_0000,
});

// CK_NOTIFICATION

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct CK_NOTIFICATION(CK_ULONG);

// CK_OBJECT_CLASS

define_enum!(CK_OBJECT_CLASS {
    CKO_PUBLIC_KEY = 0x0000_0002,
    CKO_PRIVATE_KEY = 0x0000_0003,
});

// CK_OBJECT_HANDLE

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CK_OBJECT_HANDLE(CK_ULONG);

pub const CK_INVALID_OBJECT_HANDLE: CK_OBJECT_HANDLE = CK_OBJECT_HANDLE(0x0000_0000);

pub type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;

// CK_RSA_PKCS_MGF_TYPE

define_enum!(CK_RSA_PKCS_MGF_TYPE {
    CKG_MGF1_SHA1 = 0x0000_0001,
    CKG_MGF1_SHA256 = 0x0000_0002,
    CKG_MGF1_SHA384 = 0x0000_0003,
    CKG_MGF1_SHA512 = 0x0000_0004,
    CKG_MGF1_SHA224 = 0x0000_0005,
});

// CK_RV

define_enum!(CK_RV {
    CKR_ACTION_PROHIBITED = 0x0000_001b,
    CKR_ARGUMENTS_BAD = 0x0000_0007,
    CKR_ATTRIBUTE_TYPE_INVALID = 0x0000_0012,
    CKR_ATTRIBUTE_VALUE_INVALID = 0x0000_0013,

    CKR_BUFFER_TOO_SMALL = 0x0000_0150,

    CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x0000_0191,
    CKR_CRYPTOKI_NOT_INITIALIZED = 0x0000_0190,
    CKR_CURVE_NOT_SUPPORTED = 0x0000_0140,

    CKR_DEVICE_ERROR = 0x0000_0030,
    CKR_DEVICE_MEMORY = 0x0000_0031,
    CKR_DEVICE_REMOVED = 0x0000_0032,

    CKR_FUNCTION_FAILED = 0x0000_0006,
    CKR_FUNCTION_NOT_SUPPORTED = 0x0000_0054,

    CKR_GENERAL_ERROR = 0x0000_0005,

    CKR_HOST_MEMORY = 0x0000_0002,

    CKR_KEY_FUNCTION_NOT_PERMITTED = 0x0000_0068,
    CKR_KEY_HANDLE_INVALID = 0x000_0060,
    CKR_KEY_SIZE_RANGE = 0x0000_0062,
    CKR_KEY_TYPE_INCONSISTENT = 0x0000_0063,

    CKR_LIBRARY_LOAD_FAILED = 0x0000_01c2,

    CKR_MECHANISM_INVALID = 0x0000_0070,
    CKR_MECHANISM_PARAM_INVALID = 0x0000_0071,
    CKR_MUTEX_BAD = 0x0000_01a0,
    CKR_MUTEX_NOT_LOCKED = 0x0000_01a1,

    CKR_NEED_TO_CREATE_THREADS = 0x0000_0009,

    CKR_OBJECT_HANDLE_INVALID = 0x0000_0082,
    CKR_OK = 0x0000_0000,
    CKR_OPERATION_ACTIVE = 0x0000_0090,

    CKR_PIN_EXPIRED = 0x0000_00a3,
    CKR_PIN_INCORRECT = 0x0000_00a0,
    CKR_PIN_LEN_RANGE = 0x0000_00a2,
    CKR_PIN_LOCKED = 0x0000_00a4,
    CKR_PIN_TOO_WEAK = 0x0000_01c3,

    CKR_SESSION_CLOSED = 0x0000_00b0,
    CKR_SESSION_COUNT = 0x0000_00b1,
    CKR_SESSION_EXISTS = 0x0000_00b6,
    CKR_SESSION_HANDLE_INVALID = 0x0000_00b3,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x0000_00b4,
    CKR_SESSION_READ_ONLY = 0x0000_00b5,
    CKR_SESSION_READ_ONLY_EXISTS = 0x0000_00b7,
    CKR_SESSION_READ_WRITE_EXISTS = 0x0000_00b8,
    CKR_SLOT_ID_INVALID = 0x0000_0003,

    CKR_TEMPLATE_INCOMPLETE = 0x0000_00d0,
    CKR_TOKEN_NOT_PRESENT = 0x0000_00e0,

    CKR_USER_ALREADY_LOGGED_IN = 0x0000_0100,
    CKR_USER_NOT_LOGGED_IN = 0x0000_0101,
});

// CK_SESSION_HANDLE

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CK_SESSION_HANDLE(CK_ULONG);

pub const CK_INVALID_SESSION_HANDLE: CK_SESSION_HANDLE = CK_SESSION_HANDLE(0x0000_0000);

pub type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;

// CK_SESSION_INFO

#[derive(Debug)]
#[repr(C)]
pub struct CK_SESSION_INFO {
    pub slotID: CK_SLOT_ID,
    pub state: CK_STATE,
    pub flags: CK_OPEN_SESSION_FLAGS,
    pub ulDeviceError: CK_ULONG,
}

pub type CK_SESSION_INFO_PTR = *mut CK_SESSION_INFO;

// CK_SLOT_ID

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CK_SLOT_ID(pub CK_ULONG);

impl std::str::FromStr for CK_SLOT_ID {
    type Err = <CK_ULONG as std::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(CK_SLOT_ID(std::str::FromStr::from_str(s)?))
    }
}

pub type CK_SLOT_ID_PTR = *mut CK_SLOT_ID;

// CK_STATE

define_enum!(CK_STATE {
    CKS_RO_PUBLIC_SESSION = 0x0000_0000,
    CKS_RO_USER_FUNCTIONS = 0x0000_0001,

    CKS_RW_PUBLIC_SESSION = 0x0000_0002,
    CKS_RW_USER_FUNCTIONS = 0x0000_0003,

    CKS_RW_SO_FUNCTIONS = 0x0000_0004,
});

// CK_TOKEN_INFO

#[derive(Debug)]
#[repr(C)]
pub struct CK_TOKEN_INFO {
    pub label: [CK_UTF8CHAR; 32],
    pub manufacturerID: [CK_UTF8CHAR; 32],
    pub model: [CK_UTF8CHAR; 16],
    pub serialNumber: [CK_CHAR; 16],
    pub flags: CK_TOKEN_INFO_FLAGS,
    pub ulMaxSessionCount: CK_ULONG,
    pub ulSessionCount: CK_ULONG,
    pub ulMaxRwSessionCount: CK_ULONG,
    pub ulRwSessionCount: CK_ULONG,
    pub ulMaxPinLen: CK_ULONG,
    pub ulMinPinLen: CK_ULONG,
    pub ulTotalPublicMemory: CK_ULONG,
    pub ulFreePublicMemory: CK_ULONG,
    pub ulTotalPrivateMemory: CK_ULONG,
    pub ulFreePrivateMemory: CK_ULONG,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
    pub utcTime: [CK_CHAR; 16],
}

pub type CK_TOKEN_INFO_PTR = *mut CK_TOKEN_INFO;

// CK_ULONG

pub type CK_ULONG = std::os::raw::c_ulong;

pub type CK_ULONG_PTR = *mut CK_ULONG;

// CK_USER_TYPE

define_enum!(CK_USER_TYPE {
    CKU_SO = 0x0000_0000,
    CKU_USER = 0x0000_0001,
});

// CK_UTF8CHAR

pub type CK_UTF8CHAR = CK_BYTE;

pub type CK_UTF8CHAR_PTR = *const CK_BYTE;

// CK_VERSION

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}

impl std::fmt::Display for CK_VERSION {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}.{}", self.major, self.minor)
    }
}

// CK_VOID

pub type CK_VOID = std::ffi::c_void;
pub type CK_VOID_PTR = *mut CK_VOID;
pub type CK_VOID_PTR_CONST = *const CK_VOID;
pub type CK_VOID_PTR_PTR = *mut CK_VOID_PTR;

// Function typedefs

pub type CK_C_CloseSession = unsafe extern "C" fn(hSession: CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_DestroyObject =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Encrypt = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR_CONST,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_EncryptInit = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR_CONST,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV;
pub type CK_C_Finalize = unsafe extern "C" fn(pReserved: CK_VOID_PTR) -> CK_RV;
pub type CK_C_FindObjects = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_FindObjectsFinal = unsafe extern "C" fn(hSession: CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_FindObjectsInit = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR_CONST,
    ulCount: CK_ULONG,
) -> CK_RV;
pub type CK_C_GenerateKeyPair = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR_CONST,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR_CONST,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR_CONST,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_GetAttributeValue = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV;
pub type CK_C_GetFunctionList =
    unsafe extern "C" fn(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;
pub type CK_C_GetInfo = unsafe extern "C" fn(pInfo: CK_INFO_PTR) -> CK_RV;
pub type CK_C_GetSessionInfo =
    unsafe extern "C" fn(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR) -> CK_RV;
pub type CK_C_GetSlotList = unsafe extern "C" fn(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_GetTokenInfo =
    unsafe extern "C" fn(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV;
pub type CK_C_Initialize = unsafe extern "C" fn(pReserved: CK_C_INITIALIZE_ARGS_PTR) -> CK_RV;
pub type CK_C_Login = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV;
pub type CK_C_OpenSession = unsafe extern "C" fn(
    slotID: CK_SLOT_ID,
    flags: CK_OPEN_SESSION_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: Option<CK_NOTIFY>,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV;
pub type CK_C_Sign = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR_CONST,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV;
pub type CK_C_SignInit = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR_CONST,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV;

pub type CK_CREATEMUTEX = unsafe extern "C" fn(ppMutex: CK_VOID_PTR_PTR) -> CK_RV;
pub type CK_DESTROYMUTEX = unsafe extern "C" fn(pMutex: CK_VOID_PTR) -> CK_RV;
pub type CK_LOCKMUTEX = unsafe extern "C" fn(pMutex: CK_VOID_PTR) -> CK_RV;
pub type CK_UNLOCKMUTEX = unsafe extern "C" fn(pMutex: CK_VOID_PTR) -> CK_RV;

pub type CK_NOTIFY = unsafe extern "C" fn(
    hSession: CK_SESSION_HANDLE,
    event: CK_NOTIFICATION,
    pApplication: CK_VOID_PTR,
) -> CK_RV;

#[cfg(test)]
mod tests {
    #[test]
    fn CK_FUNCTION_LIST() {
        // CK_FUNCTION_LIST has a CK_VERSION padded to sizeof uintptr_t + 68 function pointers
        assert_eq!(
            std::mem::size_of::<super::CK_FUNCTION_LIST>(),
            std::mem::size_of::<usize>() + 68 * std::mem::size_of::<usize>(),
        );
    }
}
