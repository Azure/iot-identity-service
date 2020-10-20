// Copyright (c) Microsoft. All rights reserved.

pub(crate) unsafe extern "C" fn create_key_if_not_exists(
    id: *const std::os::raw::c_char,
    length: usize,
) -> crate::AZIOT_KEYS_STATUS {
    crate::r#catch(|| {
        let id = {
            if id.is_null() {
                return Err(crate::implementation::err_invalid_parameter(
                    "id",
                    "expected non-NULL",
                ));
            }
            let id = std::ffi::CStr::from_ptr(id);
            let id = id
                .to_str()
                .map_err(|err| crate::implementation::err_invalid_parameter("id", err))?;
            id
        };

        let locations = crate::implementation::Location::of(id)?;

        if load_inner(&locations)?.is_none() {
            let mut bytes = vec![0_u8; length];
            openssl::rand::rand_bytes(&mut bytes)?;

            create_inner(&locations, &bytes)?;
            if load_inner(&locations)?.is_none() {
                return Err(crate::implementation::err_external(
                    "key created successfully but could not be found",
                ));
            }
        }

        Ok(())
    })
}

pub(crate) unsafe extern "C" fn load_key(
    id: *const std::os::raw::c_char,
) -> crate::AZIOT_KEYS_STATUS {
    crate::r#catch(|| {
        let id = {
            if id.is_null() {
                return Err(crate::implementation::err_invalid_parameter(
                    "id",
                    "expected non-NULL",
                ));
            }
            let id = std::ffi::CStr::from_ptr(id);
            let id = id
                .to_str()
                .map_err(|err| crate::implementation::err_invalid_parameter("id", err))?;
            id
        };

        let locations = crate::implementation::Location::of(id)?;

        if load_inner(&locations)?.is_none() {
            return Err(crate::implementation::err_invalid_parameter(
                "id",
                "not found",
            ));
        }

        Ok(())
    })
}

pub(crate) unsafe extern "C" fn import_key(
    id: *const std::os::raw::c_char,
    bytes: *const u8,
    bytes_len: usize,
) -> crate::AZIOT_KEYS_STATUS {
    crate::r#catch(|| {
        let id = {
            if id.is_null() {
                return Err(crate::implementation::err_invalid_parameter(
                    "id",
                    "expected non-NULL",
                ));
            }
            let id = std::ffi::CStr::from_ptr(id);
            let id = id
                .to_str()
                .map_err(|err| crate::implementation::err_invalid_parameter("id", err))?;
            id
        };

        if bytes.is_null() {
            return Err(crate::implementation::err_invalid_parameter(
                "bytes",
                "expected non-NULL",
            ));
        }

        let bytes = std::slice::from_raw_parts(bytes, bytes_len);

        let locations = crate::implementation::Location::of(id)?;

        create_inner(&locations, bytes)?;
        if load_inner(&locations)?.is_none() {
            return Err(crate::implementation::err_external(
                "key created successfully but could not be found",
            ));
        }

        Ok(())
    })
}

pub(crate) unsafe extern "C" fn derive_key(
    base_id: *const std::os::raw::c_char,
    derivation_data: *const u8,
    derivation_data_len: usize,
    derived_key: *mut std::os::raw::c_uchar,
    derived_key_len: *mut usize,
) -> crate::AZIOT_KEYS_STATUS {
    crate::r#catch(|| {
        let base_id = {
            if base_id.is_null() {
                return Err(crate::implementation::err_invalid_parameter(
                    "base_id",
                    "expected non-NULL",
                ));
            }
            let base_id = std::ffi::CStr::from_ptr(base_id);
            let base_id = base_id
                .to_str()
                .map_err(|err| crate::implementation::err_invalid_parameter("base_id", err))?;
            base_id
        };

        let mut derived_key_len_out = std::ptr::NonNull::new(derived_key_len).ok_or_else(|| {
            crate::implementation::err_invalid_parameter("derived_key_len", "expected non-NULL")
        })?;

        let locations = crate::implementation::Location::of(base_id)?;

        let base_key = match load_inner(&locations)? {
            Some(key) => key,
            None => {
                return Err(crate::implementation::err_invalid_parameter(
                    "base_id",
                    "key not found",
                ))
            }
        };

        let expected_derived_key =
            derive_key_common(&base_key, derivation_data, derivation_data_len)?;
        let expected_derived_key_len = expected_derived_key.len();

        let actual_derived_key_len = *derived_key_len_out.as_ref();

        *derived_key_len_out.as_mut() = expected_derived_key_len;

        if !derived_key.is_null() {
            let expected_derived_key_len = expected_derived_key.len();

            if actual_derived_key_len < expected_derived_key_len {
                return Err(crate::implementation::err_invalid_parameter(
                    "derived_key",
                    "insufficient size",
                ));
            }

            let derived_key_out =
                std::slice::from_raw_parts_mut(derived_key, actual_derived_key_len);

            derived_key_out[..expected_derived_key_len].copy_from_slice(&expected_derived_key);
            *derived_key_len_out.as_mut() = expected_derived_key_len;
        }

        Ok(())
    })
}

pub(crate) unsafe fn sign(
    locations: &[crate::implementation::Location],
    mechanism: crate::AZIOT_KEYS_SIGN_MECHANISM,
    parameters: *const std::ffi::c_void,
    digest: &[u8],
) -> Result<(usize, Vec<u8>), crate::AZIOT_KEYS_STATUS> {
    use hmac::{Mac, NewMac};

    let key = match load_inner(locations)? {
        Some(key) => key,
        None => {
            return Err(crate::implementation::err_invalid_parameter(
                "id",
                "key not found",
            ))
        }
    };

    let (key, mechanism, _) = if mechanism == crate::AZIOT_KEYS_SIGN_MECHANISM_DERIVED {
        derive_key_for_sign(&key, parameters)?
    } else {
        (key, mechanism, parameters)
    };

    if mechanism != crate::AZIOT_KEYS_SIGN_MECHANISM_HMAC_SHA256 {
        return Err(crate::implementation::err_invalid_parameter(
            "mechanism",
            "unrecognized value",
        ));
    }

    let mut signer = hmac::Hmac::<sha2::Sha256>::new_varkey(&key)
        .map_err(crate::implementation::err_external)?;

    signer.update(digest);

    let signature = signer.finalize();
    let signature = signature.into_bytes().to_vec();
    Ok((signature.len(), signature))
}

pub(crate) unsafe fn verify(
    locations: &[crate::implementation::Location],
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, crate::AZIOT_KEYS_STATUS> {
    use hmac::{Mac, NewMac};

    let key = match load_inner(locations)? {
        Some(key) => key,
        None => {
            return Err(crate::implementation::err_invalid_parameter(
                "id",
                "key not found",
            ))
        }
    };

    let mut signer = hmac::Hmac::<sha2::Sha256>::new_varkey(&key)
        .map_err(crate::implementation::err_external)?;

    signer.update(digest);

    // As hmac's docs say, it's important to use `verify` here instead of just running `finalize().into_bytes()` and comparing the signatures,
    // because `verify` makes sure to be constant-time.
    let ok = signer.verify(signature).is_ok();
    Ok(ok)
}

// Ciphertext is formatted as:
//
// - Encryption scheme version (1 byte); v1 == 0x01_u8
// - Tag (16 bytes) (16 bytes is the tag size for AES-256-GCM)
// - Actual ciphertext

pub(crate) unsafe fn encrypt(
    locations: &[crate::implementation::Location],
    mechanism: crate::AZIOT_KEYS_ENCRYPT_MECHANISM,
    parameters: *const std::ffi::c_void,
    plaintext: &[u8],
) -> Result<(usize, Vec<u8>), crate::AZIOT_KEYS_STATUS> {
    let key = match load_inner(locations)? {
        Some(key) => key,
        None => {
            return Err(crate::implementation::err_invalid_parameter(
                "id",
                "key not found",
            ))
        }
    };

    let (key, mechanism, parameters) = if mechanism == crate::AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED {
        derive_key_for_encrypt(&key, parameters)?
    } else {
        (key, mechanism, parameters)
    };

    if mechanism != crate::AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD {
        return Err(crate::implementation::err_invalid_parameter(
            "mechanism",
            "unrecognized value",
        ));
    }

    let (iv, aad) = {
        if parameters.is_null() {
            return Err(crate::implementation::err_invalid_parameter(
                "parameters",
                "expected non-NULL",
            ));
        }

        let parameters = parameters as *const crate::AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS;
        let parameters = &*parameters;

        let iv = std::slice::from_raw_parts(parameters.iv, parameters.iv_len);
        let aad = std::slice::from_raw_parts(parameters.aad, parameters.aad_len);
        (iv, aad)
    };

    let cipher = openssl::symm::Cipher::aes_256_gcm();

    let mut tag = vec![0_u8; 16];
    let ciphertext =
        openssl::symm::encrypt_aead(cipher, &key, Some(iv), aad, plaintext, &mut tag[..])?;

    let mut result = vec![0x01_u8];
    result.extend_from_slice(&tag);
    result.extend_from_slice(&ciphertext);
    Ok((result.len(), result))
}

pub(crate) unsafe fn decrypt(
    locations: &[crate::implementation::Location],
    mechanism: crate::AZIOT_KEYS_ENCRYPT_MECHANISM,
    parameters: *const std::ffi::c_void,
    ciphertext: &[u8],
) -> Result<(usize, Vec<u8>), crate::AZIOT_KEYS_STATUS> {
    let key = match load_inner(locations)? {
        Some(key) => key,
        None => {
            return Err(crate::implementation::err_invalid_parameter(
                "id",
                "key not found",
            ))
        }
    };

    let (key, mechanism, parameters) = if mechanism == crate::AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED {
        derive_key_for_encrypt(&key, parameters)?
    } else {
        (key, mechanism, parameters)
    };

    if mechanism != crate::AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD {
        return Err(crate::implementation::err_invalid_parameter(
            "mechanism",
            "unrecognized value",
        ));
    }

    let (iv, aad) = {
        if parameters.is_null() {
            return Err(crate::implementation::err_invalid_parameter(
                "parameters",
                "expected non-NULL",
            ));
        }

        let parameters = parameters as *const crate::AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS;
        let parameters = &*parameters;

        let iv = std::slice::from_raw_parts(parameters.iv, parameters.iv_len);
        let aad = std::slice::from_raw_parts(parameters.aad, parameters.aad_len);
        (iv, aad)
    };

    let cipher = openssl::symm::Cipher::aes_256_gcm();

    if ciphertext.len() < 1 + 16 {
        return Err(crate::implementation::err_invalid_parameter(
            "ciphertext",
            "expected non-NULL",
        ));
    }
    if ciphertext[0] != 0x01 {
        return Err(crate::implementation::err_invalid_parameter(
            "ciphertext",
            "expected non-NULL",
        ));
    }

    let tag = &ciphertext[1..=16];
    let ciphertext = &ciphertext[17..];

    let plaintext = openssl::symm::decrypt_aead(cipher, &key, Some(iv), aad, ciphertext, tag)?;

    Ok((plaintext.len(), plaintext))
}

fn load_inner(
    locations: &[crate::implementation::Location],
) -> Result<Option<Vec<u8>>, crate::AZIOT_KEYS_STATUS> {
    for location in locations {
        match location {
            crate::implementation::Location::Filesystem(path) => match std::fs::read(path) {
                Ok(key_bytes) => return Ok(Some(key_bytes)),
                Err(ref err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(err) => return Err(crate::implementation::err_external(err)),
            },

            // PKCS#11 symmetric keys are not supported
            crate::implementation::Location::Pkcs11 { .. } => (),
        }
    }

    Err(crate::implementation::err_external(
        "no valid location for symmetric key",
    ))
}

fn create_inner(
    locations: &[crate::implementation::Location],
    bytes: &[u8],
) -> Result<(), crate::AZIOT_KEYS_STATUS> {
    for location in locations {
        match location {
            crate::implementation::Location::Filesystem(path) => {
                std::fs::write(path, bytes).map_err(crate::implementation::err_external)?;
                return Ok(());
            }

            // PKCS#11 symmetric keys are not supported
            crate::implementation::Location::Pkcs11 { .. } => (),
        }
    }

    Err(crate::implementation::err_external(
        "no valid location for symmetric key",
    ))
}

unsafe fn derive_key_for_sign(
    key: &[u8],
    parameters: *const std::ffi::c_void,
) -> Result<
    (
        Vec<u8>,
        crate::AZIOT_KEYS_SIGN_MECHANISM,
        *const std::ffi::c_void,
    ),
    crate::AZIOT_KEYS_STATUS,
> {
    if parameters.is_null() {
        return Err(crate::implementation::err_invalid_parameter(
            "parameters",
            "expected non-NULL",
        ));
    }

    let parameters = parameters as *const crate::AZIOT_KEYS_SIGN_DERIVED_PARAMETERS;
    let parameters = &*parameters;

    let signature = derive_key_common(
        key,
        parameters.derivation_data,
        parameters.derivation_data_len,
    )?;

    Ok((signature, parameters.mechanism, parameters.parameters))
}

unsafe fn derive_key_for_encrypt(
    key: &[u8],
    parameters: *const std::ffi::c_void,
) -> Result<
    (
        Vec<u8>,
        crate::AZIOT_KEYS_ENCRYPT_MECHANISM,
        *const std::ffi::c_void,
    ),
    crate::AZIOT_KEYS_STATUS,
> {
    if parameters.is_null() {
        return Err(crate::implementation::err_invalid_parameter(
            "parameters",
            "expected non-NULL",
        ));
    }

    let parameters = parameters as *const crate::AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS;
    let parameters = &*parameters;

    let signature = derive_key_common(
        key,
        parameters.derivation_data,
        parameters.derivation_data_len,
    )?;

    Ok((signature, parameters.mechanism, parameters.parameters))
}

unsafe fn derive_key_common(
    key: &[u8],
    derivation_data: *const std::os::raw::c_uchar,
    derivation_data_len: usize,
) -> Result<Vec<u8>, crate::AZIOT_KEYS_STATUS> {
    use hmac::{Mac, NewMac};

    if derivation_data.is_null() {
        return Err(crate::implementation::err_invalid_parameter(
            "derivation_data",
            "expected non-NULL",
        ));
    }

    let derivation_data = std::slice::from_raw_parts(derivation_data, derivation_data_len);

    let mut signer = hmac::Hmac::<sha2::Sha256>::new_varkey(&key)
        .map_err(crate::implementation::err_external)?;

    signer.update(derivation_data);

    let signature = signer.finalize();
    let signature = signature.into_bytes().to_vec();
    Ok(signature)
}
