// Copyright (c) Microsoft. All rights reserved.

pub(crate) unsafe extern "C" fn create_key_if_not_exists(
    id: *const std::os::raw::c_char,
    usage: crate::AZIOT_KEYS_KEY_USAGE,
) -> crate::AZIOT_KEYS_RC {
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
            create_inner(&locations, CreateMethod::Generate, usage)?;
            if load_inner(&locations)?.is_none() {
                return Err(crate::implementation::err_external(
                    "key created successfully but could not be found",
                ));
            }
        }

        Ok(())
    })
}

pub(crate) unsafe extern "C" fn load_key(id: *const std::os::raw::c_char) -> crate::AZIOT_KEYS_RC {
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
    usage: crate::AZIOT_KEYS_KEY_USAGE,
) -> crate::AZIOT_KEYS_RC {
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

        create_inner(&locations, CreateMethod::Import(bytes), usage)?;
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
) -> crate::AZIOT_KEYS_RC {
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
) -> Result<(usize, Vec<u8>), crate::AZIOT_KEYS_RC> {
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

    match key {
        Key::FileSystem(key) => {
            use hmac::{Mac, NewMac};

            let mut signer = hmac::Hmac::<sha2::Sha256>::new_varkey(&key)
                .map_err(crate::implementation::err_external)?;

            signer.update(digest);

            let signature = signer.finalize();
            let signature = signature.into_bytes().to_vec();
            Ok((signature.len(), signature))
        }

        Key::Pkcs11(key) => {
            let mut signature = vec![0_u8; 32];
            let signature_len = key
                .sign(digest, &mut signature)
                .map_err(crate::implementation::err_external)?;
            let signature_len =
                std::convert::TryInto::try_into(signature_len).expect("CK_ULONG -> usize");
            signature.truncate(signature_len);
            Ok((signature_len, signature))
        }
    }
}

pub(crate) unsafe fn verify(
    locations: &[crate::implementation::Location],
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, crate::AZIOT_KEYS_RC> {
    let key = match load_inner(locations)? {
        Some(key) => key,
        None => {
            return Err(crate::implementation::err_invalid_parameter(
                "id",
                "key not found",
            ))
        }
    };

    match key {
        Key::FileSystem(key) => {
            use hmac::{Mac, NewMac};

            let mut signer = hmac::Hmac::<sha2::Sha256>::new_varkey(&key)
                .map_err(crate::implementation::err_external)?;

            signer.update(digest);

            // As hmac's docs say, it's important to use `verify` here instead of just running `finalize().into_bytes()` and comparing the signatures,
            // because `verify` makes sure to be constant-time.
            let ok = signer.verify(signature).is_ok();
            Ok(ok)
        }

        Key::Pkcs11(key) => {
            let ok = key
                .verify(digest, signature)
                .map_err(crate::implementation::err_external)?;
            Ok(ok)
        }
    }
}

// Ciphertext is formatted as:
//
// - Encryption scheme version (1 byte)
// - Rest
//
//
// # v1 (0x01_u8)
//
// v1 keys are the format used by IoT Edge 1.1 and earlier. The format of "Rest" is:
//
// - Tag (16 bytes)
// - Actual ciphertext (`len(plaintext)` rounded up by `len(block size)`)
//
//
// # v2 (0x02_08)
//
// v2 keys are the format used by v1.2 and higher. The format of "Rest" is:
//
// - Actual ciphertext (`len(plaintext)` rounded up by `len(block size)`)
// - Tag (16 bytes)
//
// This format is what is used by PKCS#11 [1], so we also use it for filesystem keys.
// This way a filesystem key can be imported into a PKCS#11 device and
// still be used to decrypt secrets that were encrypted when it was on the filesystem.
//
//
// # Miscellaneous
//
// - Filesystem keys use AES-256-GCM. PKCS#11 keys use AES-GCM with unspecified key length (chosen by the token).
//   For PKCS#11 keys that we generate, we try to generate an AES-256 key, then fall back to an AES-128 key
//   if the library doesn't support AES-256; see `pkcs11::Session::generate_key`
//
// - For AES, `len(block size)` = 128 bits = 16 bytes.
//
// - `len(tag)` was chosen to be 16 bytes because that's the best modern value for AES-GCM.
//
// - Decrypting supports multiple versions, but encrypting new secrets always uses the latest version,
//   since the version is an implementation detail and not controllable by the caller.
//   So Edge modules running under edged can decrypt v1 secrets that were created by iotedged,
//   but if they re-encrypt those secrets they'll get v2 secrets.
//
//
// # Refs
//
// [1]: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html#_Toc370634467

pub(crate) unsafe fn encrypt(
    locations: &[crate::implementation::Location],
    mechanism: crate::AZIOT_KEYS_ENCRYPT_MECHANISM,
    parameters: *const std::ffi::c_void,
    plaintext: &[u8],
) -> Result<(usize, Vec<u8>), crate::AZIOT_KEYS_RC> {
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

        let parameters = &*parameters.cast::<crate::AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS>();

        let iv = std::slice::from_raw_parts(parameters.iv, parameters.iv_len);
        let aad = std::slice::from_raw_parts(parameters.aad, parameters.aad_len);
        (iv, aad)
    };

    let cipher = openssl::symm::Cipher::aes_256_gcm();

    match key {
        Key::FileSystem(key) => {
            let mut tag = [0_u8; 16];
            let mut ciphertext =
                openssl::symm::encrypt_aead(cipher, &key, Some(iv), aad, plaintext, &mut tag)?;

            ciphertext.insert(0, 0x02);
            ciphertext.extend_from_slice(&tag);
            Ok((ciphertext.len(), ciphertext))
        }

        Key::Pkcs11(key) => {
            // We can use the block size of AES-256-GCM from openssl even though the token didn't necessarily use AES-256-GCM,
            // because all AES ciphers have the same block size by definition.
            let mut ciphertext = vec![0_u8; 1 + plaintext.len() + cipher.block_size() + 16];

            ciphertext[0] = 0x02;

            let ciphertext_len = key
                .encrypt(iv, aad, plaintext, &mut ciphertext[1..])
                .map_err(crate::implementation::err_external)?;
            let ciphertext_len: usize =
                std::convert::TryInto::try_into(ciphertext_len).expect("CK_ULONG -> usize");
            let ciphertext_len = ciphertext_len + 1;
            ciphertext.truncate(ciphertext_len);

            Ok((ciphertext_len, ciphertext))
        }
    }
}

pub(crate) unsafe fn decrypt(
    locations: &[crate::implementation::Location],
    mechanism: crate::AZIOT_KEYS_ENCRYPT_MECHANISM,
    parameters: *const std::ffi::c_void,
    ciphertext: &[u8],
) -> Result<(usize, Vec<u8>), crate::AZIOT_KEYS_RC> {
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

        let parameters = &*parameters.cast::<crate::AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS>();

        let iv = std::slice::from_raw_parts(parameters.iv, parameters.iv_len);
        let aad = std::slice::from_raw_parts(parameters.aad, parameters.aad_len);
        (iv, aad)
    };

    let cipher = openssl::symm::Cipher::aes_256_gcm();

    let (&version, ciphertext) = ciphertext
        .split_first()
        .ok_or_else(|| crate::implementation::err_invalid_parameter("ciphertext", "malformed"))?;

    if ciphertext.len() < 16 {
        return Err(crate::implementation::err_invalid_parameter(
            "ciphertext",
            "malformed",
        ));
    }

    match key {
        Key::FileSystem(key) => {
            let (ciphertext, tag) = match version {
                0x01 => {
                    let (tag, ciphertext) = ciphertext.split_at(16);
                    (ciphertext, tag)
                }

                0x02 => {
                    ciphertext.split_at(ciphertext.len() - 16)
                }

                version => {
                    return Err(crate::implementation::err_invalid_parameter(
                        "ciphertext",
                        format!("unknown version {:?}", version),
                    ));
                }
            };

            let plaintext =
                openssl::symm::decrypt_aead(cipher, &key, Some(iv), aad, ciphertext, tag)?;
            Ok((plaintext.len(), plaintext))
        }

        Key::Pkcs11(key) => {
            let ciphertext = match version {
                0x02 => ciphertext,

                version => {
                    return Err(crate::implementation::err_invalid_parameter(
                        "ciphertext",
                        format!("unknown version {:?}", version),
                    ));
                }
            };

            let mut plaintext = vec![0_u8; ciphertext.len() - 16];
            let plaintext_len = key
                .decrypt(iv, aad, ciphertext, &mut plaintext)
                .map_err(crate::implementation::err_external)?;
            let plaintext_len =
                std::convert::TryInto::try_into(plaintext_len).expect("CK_ULONG -> usize");
            plaintext.truncate(plaintext_len);
            Ok((plaintext_len, plaintext))
        }
    }
}

enum Key {
    FileSystem(Vec<u8>),
    Pkcs11(pkcs11::Key),
}

fn load_inner(
    locations: &[crate::implementation::Location],
) -> Result<Option<Key>, crate::AZIOT_KEYS_RC> {
    for location in locations {
        match location {
            crate::implementation::Location::Filesystem(path) => match std::fs::read(path) {
                Ok(key_bytes) => return Ok(Some(Key::FileSystem(key_bytes))),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                Err(err) => return Err(crate::implementation::err_external(err)),
            },

            crate::implementation::Location::Pkcs11 { lib_path, uri } => {
                let pkcs11_context = pkcs11::Context::load(lib_path.clone())
                    .map_err(crate::implementation::err_external)?;
                let pkcs11_slot = pkcs11_context
                    .find_slot(&uri.slot_identifier)
                    .map_err(crate::implementation::err_external)?;
                let pkcs11_session = pkcs11_context
                    .open_session(pkcs11_slot, uri.pin.clone())
                    .map_err(crate::implementation::err_external)?;

                match pkcs11_session.get_key(uri.object_label.as_ref().map(AsRef::as_ref)) {
                    Ok(key_pair) => return Ok(Some(Key::Pkcs11(key_pair))),

                    Err(pkcs11::GetKeyError::KeyDoesNotExist) => (),

                    Err(err) => return Err(crate::implementation::err_external(err)),
                }
            }
        }
    }

    Ok(None)
}

#[derive(Clone, Copy)]
enum CreateMethod<'a> {
    Generate,
    Import(&'a [u8]),
}

fn create_inner(
    locations: &[crate::implementation::Location],
    create_method: CreateMethod<'_>,
    usage: crate::AZIOT_KEYS_KEY_USAGE,
) -> Result<(), crate::AZIOT_KEYS_RC> {
    for location in locations {
        match location {
            crate::implementation::Location::Filesystem(path) => {
                let result = match create_method {
                    CreateMethod::Generate => {
                        // Filesystem uses AES-256-GCM for encryption keys and HMAC-SHA256 for hash keys,
                        // so it uses 256-bit == 32-byte keys for both.

                        let mut bytes = vec![0_u8; 32];
                        openssl::rand::rand_bytes(&mut bytes)?;
                        std::fs::write(path, bytes)
                    }

                    CreateMethod::Import(bytes) => std::fs::write(path, bytes),
                };
                let () = result.map_err(crate::implementation::err_external)?;
                return Ok(());
            }

            crate::implementation::Location::Pkcs11 { lib_path, uri } => {
                let usage = match usage {
                    #[allow(unreachable_patterns)] // DERIVE and SIGN are the same constant
                    crate::AZIOT_KEYS_KEY_USAGE_DERIVE | crate::AZIOT_KEYS_KEY_USAGE_SIGN => {
                        pkcs11::KeyUsage::Hmac
                    }
                    crate::AZIOT_KEYS_KEY_USAGE_ENCRYPT => pkcs11::KeyUsage::Aes,
                    _ => {
                        return Err(crate::implementation::err_invalid_parameter(
                            "usage",
                            "unrecognized value",
                        ))
                    }
                };

                let pkcs11_context = pkcs11::Context::load(lib_path.clone())
                    .map_err(crate::implementation::err_external)?;
                let pkcs11_slot = pkcs11_context
                    .find_slot(&uri.slot_identifier)
                    .map_err(crate::implementation::err_external)?;
                let pkcs11_session = pkcs11_context
                    .open_session(pkcs11_slot, uri.pin.clone())
                    .map_err(crate::implementation::err_external)?;

                match create_method {
                    CreateMethod::Generate => {
                        let result = pkcs11_session
                            .generate_key(uri.object_label.as_ref().map(AsRef::as_ref), usage);
                        match result {
                            Ok(_) => return Ok(()),

                            Err(pkcs11::GenerateKeyError::GenerateKeyFailed(
                                pkcs11_sys::CKR_FUNCTION_NOT_SUPPORTED,
                            )) |
                            // Some PKCS#11 implementations like Cryptoauthlib don't support `C_GenerateKey(CKM_GENERIC_SECRET_KEY_GEN)`
                            Err(pkcs11::GenerateKeyError::GenerateKeyFailed(
                                pkcs11_sys::CKR_MECHANISM_INVALID,
                            )) => (),

                            Err(err) => return Err(crate::implementation::err_external(err)),
                        }
                    }

                    CreateMethod::Import(bytes) => {
                        // TODO: Verify if CAL actually smashes the stack for keys that are too large,
                        // and if not, if it returns a better error than CKR_GENERAL_ERROR
                        let result = pkcs11_session.import_key(
                            bytes,
                            uri.object_label.as_ref().map(AsRef::as_ref),
                            usage,
                        );
                        match result {
                            Ok(_) => return Ok(()),

                            // No better error from some PKCS#11 implementations like Cryptoauthlib than CKR_GENERAL_ERROR
                            Err(pkcs11::ImportKeyError::CreateObjectFailed(_)) => (),

                            Err(err) => return Err(crate::implementation::err_external(err)),
                        }
                    }
                }
            }
        }
    }

    Err(crate::implementation::err_external(
        "no valid location for symmetric key",
    ))
}

unsafe fn derive_key_for_sign(
    key: &Key,
    parameters: *const std::ffi::c_void,
) -> Result<
    (
        Key,
        crate::AZIOT_KEYS_SIGN_MECHANISM,
        *const std::ffi::c_void,
    ),
    crate::AZIOT_KEYS_RC,
> {
    if parameters.is_null() {
        return Err(crate::implementation::err_invalid_parameter(
            "parameters",
            "expected non-NULL",
        ));
    }

    let parameters = &*parameters.cast::<crate::AZIOT_KEYS_SIGN_DERIVED_PARAMETERS>();

    let signature = derive_key_common(
        key,
        parameters.derivation_data,
        parameters.derivation_data_len,
    )?;

    let derived_key = Key::FileSystem(signature);

    Ok((derived_key, parameters.mechanism, parameters.parameters))
}

unsafe fn derive_key_for_encrypt(
    key: &Key,
    parameters: *const std::ffi::c_void,
) -> Result<
    (
        Key,
        crate::AZIOT_KEYS_ENCRYPT_MECHANISM,
        *const std::ffi::c_void,
    ),
    crate::AZIOT_KEYS_RC,
> {
    if parameters.is_null() {
        return Err(crate::implementation::err_invalid_parameter(
            "parameters",
            "expected non-NULL",
        ));
    }

    let parameters = &*parameters.cast::<crate::AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS>();

    let signature = derive_key_common(
        key,
        parameters.derivation_data,
        parameters.derivation_data_len,
    )?;

    let derived_key = Key::FileSystem(signature);

    Ok((derived_key, parameters.mechanism, parameters.parameters))
}

unsafe fn derive_key_common(
    key: &Key,
    derivation_data: *const std::os::raw::c_uchar,
    derivation_data_len: usize,
) -> Result<Vec<u8>, crate::AZIOT_KEYS_RC> {
    if derivation_data.is_null() {
        return Err(crate::implementation::err_invalid_parameter(
            "derivation_data",
            "expected non-NULL",
        ));
    }

    let derivation_data = std::slice::from_raw_parts(derivation_data, derivation_data_len);

    match key {
        Key::FileSystem(key) => {
            use hmac::{Mac, NewMac};

            let mut signer = hmac::Hmac::<sha2::Sha256>::new_varkey(&key)
                .map_err(crate::implementation::err_external)?;

            signer.update(derivation_data);

            let signature = signer.finalize();
            let signature = signature.into_bytes().to_vec();
            Ok(signature)
        }

        Key::Pkcs11(key) => {
            let mut signature = vec![0_u8; 32];
            let signature_len = key
                .sign(derivation_data, &mut signature)
                .map_err(crate::implementation::err_external)?;
            let signature_len =
                std::convert::TryInto::try_into(signature_len).expect("CK_ULONG -> usize");
            signature.truncate(signature_len);
            Ok(signature)
        }
    }
}
