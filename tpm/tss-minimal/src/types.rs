pub use types_sys as sys;

pub const fn fill_tpm2b_buffer<const N: usize>(buf: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    let mut i = 0;
    while i < N && i < buf.len() {
        out[i] = buf[i];
        i += 1;
    }
    out
}

const ENDORSEMENT_KEY_POLICY: &[u8; 32] = &[
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
];

/// TCG EK Credential Profile: B.3.3 Template L-1
pub const EK_RSA_TEMPLATE: sys::TPM2B_PUBLIC = sys::TPM2B_PUBLIC {
    size: 0,
    publicArea: sys::TPMT_PUBLIC {
        type_: sys::DEF_TPM2_ALG_RSA,
        nameAlg: sys::DEF_TPM2_ALG_SHA256,
        objectAttributes: sys::DEF_TPMA_OBJECT_FIXEDTPM
            | sys::DEF_TPMA_OBJECT_FIXEDPARENT
            | sys::DEF_TPMA_OBJECT_SENSITIVEDATAORIGIN
            | sys::DEF_TPMA_OBJECT_ADMINWITHPOLICY
            | sys::DEF_TPMA_OBJECT_RESTRICTED
            | sys::DEF_TPMA_OBJECT_DECRYPT,
        authPolicy: sys::TPM2B_AUTH {
            size: ENDORSEMENT_KEY_POLICY.len() as _,
            buffer: fill_tpm2b_buffer(ENDORSEMENT_KEY_POLICY),
        },
        parameters: sys::TPMU_PUBLIC_PARMS {
            rsaDetail: sys::TPMS_RSA_PARMS {
                symmetric: sys::TPMT_SYM_DEF_OBJECT {
                    algorithm: sys::DEF_TPM2_ALG_AES,
                    keyBits: sys::TPMU_SYM_KEY_BITS { aes: 128 },
                    mode: sys::TPMU_SYM_MODE {
                        aes: sys::DEF_TPM2_ALG_CFB,
                    },
                },
                scheme: sys::TPMT_RSA_SCHEME {
                    scheme: sys::DEF_TPM2_ALG_NULL,
                    details: sys::TPMU_ASYM_SCHEME {
                        anySig: sys::TPMS_SCHEME_HASH {
                            hashAlg: sys::DEF_TPM2_ALG_NULL,
                        },
                    },
                },
                keyBits: 2048,
                exponent: 0,
            },
        },
        unique: sys::TPMU_PUBLIC_ID {
            rsa: sys::TPM2B_PUBLIC_KEY_RSA {
                size: 256,
                buffer: fill_tpm2b_buffer(&[]),
            },
        },
    },
};

/// TCG EK Credential Profile: B.3.3 Template L-2
pub const EK_ECC_TEMPLATE: sys::TPM2B_PUBLIC = sys::TPM2B_PUBLIC {
    size: 0,
    publicArea: sys::TPMT_PUBLIC {
        type_: sys::DEF_TPM2_ALG_ECC,
        nameAlg: sys::DEF_TPM2_ALG_SHA256,
        objectAttributes: sys::DEF_TPMA_OBJECT_FIXEDTPM
            | sys::DEF_TPMA_OBJECT_FIXEDPARENT
            | sys::DEF_TPMA_OBJECT_SENSITIVEDATAORIGIN
            | sys::DEF_TPMA_OBJECT_ADMINWITHPOLICY
            | sys::DEF_TPMA_OBJECT_RESTRICTED
            | sys::DEF_TPMA_OBJECT_DECRYPT,
        authPolicy: sys::TPM2B_AUTH {
            size: ENDORSEMENT_KEY_POLICY.len() as _,
            buffer: fill_tpm2b_buffer(ENDORSEMENT_KEY_POLICY),
        },
        parameters: sys::TPMU_PUBLIC_PARMS {
            eccDetail: sys::TPMS_ECC_PARMS {
                symmetric: sys::TPMT_SYM_DEF_OBJECT {
                    algorithm: sys::DEF_TPM2_ALG_AES,
                    keyBits: sys::TPMU_SYM_KEY_BITS { aes: 128 },
                    mode: sys::TPMU_SYM_MODE {
                        aes: sys::DEF_TPM2_ALG_CFB,
                    },
                },
                scheme: sys::TPMT_ECC_SCHEME {
                    scheme: sys::DEF_TPM2_ALG_NULL,
                    details: sys::TPMU_ASYM_SCHEME {
                        anySig: sys::TPMS_SCHEME_HASH {
                            hashAlg: sys::DEF_TPM2_ALG_NULL,
                        },
                    },
                },
                curveID: sys::DEF_TPM2_ECC_NIST_P256,
                kdf: sys::TPMT_KDF_SCHEME {
                    scheme: sys::DEF_TPM2_ALG_NULL,
                    details: sys::TPMU_KDF_SCHEME {
                        mgf1: sys::TPMS_SCHEME_HASH {
                            hashAlg: sys::DEF_TPM2_ALG_NULL,
                        },
                    },
                },
            },
        },
        unique: sys::TPMU_PUBLIC_ID {
            ecc: sys::TPMS_ECC_POINT {
                x: sys::TPM2B_ECC_PARAMETER {
                    size: 32,
                    buffer: fill_tpm2b_buffer(&[]),
                },
                y: sys::TPM2B_ECC_PARAMETER {
                    size: 32,
                    buffer: fill_tpm2b_buffer(&[]),
                },
            },
        },
    },
};

/// TCG TPM v2.0 Provisioning Guidance: 7.5.1 Storage Primary Key (SRK) Templates
pub const SRK_RSA_TEMPLATE: sys::TPM2B_PUBLIC = sys::TPM2B_PUBLIC {
    size: 0,
    publicArea: sys::TPMT_PUBLIC {
        type_: sys::DEF_TPM2_ALG_RSA,
        nameAlg: sys::DEF_TPM2_ALG_SHA256,
        objectAttributes: sys::DEF_TPMA_OBJECT_FIXEDTPM
            | sys::DEF_TPMA_OBJECT_FIXEDPARENT
            | sys::DEF_TPMA_OBJECT_SENSITIVEDATAORIGIN
            | sys::DEF_TPMA_OBJECT_USERWITHAUTH
            | sys::DEF_TPMA_OBJECT_NODA
            | sys::DEF_TPMA_OBJECT_RESTRICTED
            | sys::DEF_TPMA_OBJECT_DECRYPT,
        authPolicy: sys::TPM2B_AUTH {
            size: 0,
            buffer: fill_tpm2b_buffer(&[]),
        },
        parameters: sys::TPMU_PUBLIC_PARMS {
            rsaDetail: sys::TPMS_RSA_PARMS {
                symmetric: sys::TPMT_SYM_DEF_OBJECT {
                    algorithm: sys::DEF_TPM2_ALG_AES,
                    keyBits: sys::TPMU_SYM_KEY_BITS { aes: 128 },
                    mode: sys::TPMU_SYM_MODE {
                        aes: sys::DEF_TPM2_ALG_CFB,
                    },
                },
                scheme: sys::TPMT_RSA_SCHEME {
                    scheme: sys::DEF_TPM2_ALG_NULL,
                    details: sys::TPMU_ASYM_SCHEME {
                        anySig: sys::TPMS_SCHEME_HASH {
                            hashAlg: sys::DEF_TPM2_ALG_NULL,
                        },
                    },
                },
                keyBits: 2048,
                exponent: 0,
            },
        },
        unique: sys::TPMU_PUBLIC_ID {
            rsa: sys::TPM2B_PUBLIC_KEY_RSA {
                size: 256,
                buffer: fill_tpm2b_buffer(&[]),
            },
        },
    },
};

/// TCG TPM Provisioning Guidance: 7.5.1 Storage Primary Key (SRK) Templates
pub const SRK_ECC_TEMPLATE: sys::TPM2B_PUBLIC = sys::TPM2B_PUBLIC {
    size: 0,
    publicArea: sys::TPMT_PUBLIC {
        type_: sys::DEF_TPM2_ALG_ECC,
        nameAlg: sys::DEF_TPM2_ALG_SHA256,
        objectAttributes: sys::DEF_TPMA_OBJECT_FIXEDTPM
            | sys::DEF_TPMA_OBJECT_FIXEDPARENT
            | sys::DEF_TPMA_OBJECT_SENSITIVEDATAORIGIN
            | sys::DEF_TPMA_OBJECT_USERWITHAUTH
            | sys::DEF_TPMA_OBJECT_NODA
            | sys::DEF_TPMA_OBJECT_RESTRICTED
            | sys::DEF_TPMA_OBJECT_DECRYPT,
        authPolicy: sys::TPM2B_AUTH {
            size: 0,
            buffer: fill_tpm2b_buffer(&[]),
        },
        parameters: sys::TPMU_PUBLIC_PARMS {
            eccDetail: sys::TPMS_ECC_PARMS {
                symmetric: sys::TPMT_SYM_DEF_OBJECT {
                    algorithm: sys::DEF_TPM2_ALG_AES,
                    keyBits: sys::TPMU_SYM_KEY_BITS { aes: 128 },
                    mode: sys::TPMU_SYM_MODE {
                        aes: sys::DEF_TPM2_ALG_CFB,
                    },
                },
                scheme: sys::TPMT_ECC_SCHEME {
                    scheme: sys::DEF_TPM2_ALG_NULL,
                    details: sys::TPMU_ASYM_SCHEME {
                        anySig: sys::TPMS_SCHEME_HASH {
                            hashAlg: sys::DEF_TPM2_ALG_NULL,
                        },
                    },
                },
                curveID: sys::DEF_TPM2_ECC_NIST_P256,
                kdf: sys::TPMT_KDF_SCHEME {
                    scheme: sys::DEF_TPM2_ALG_NULL,
                    details: sys::TPMU_KDF_SCHEME {
                        mgf1: sys::TPMS_SCHEME_HASH {
                            hashAlg: sys::DEF_TPM2_ALG_NULL,
                        },
                    },
                },
            },
        },
        unique: sys::TPMU_PUBLIC_ID {
            ecc: sys::TPMS_ECC_POINT {
                x: sys::TPM2B_ECC_PARAMETER {
                    size: 32,
                    buffer: fill_tpm2b_buffer(&[]),
                },
                y: sys::TPM2B_ECC_PARAMETER {
                    size: 32,
                    buffer: fill_tpm2b_buffer(&[]),
                },
            },
        },
    },
};
