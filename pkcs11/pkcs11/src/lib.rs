// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    non_snake_case,
    clippy::default_trait_access,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::use_self
)]

//! A Rust wrapper to consume a PKCS#11 library. Create a [`Context`] with [`Context::load`] to get started.

mod context;
pub use context::{Context, GetTokenInfoError, ListSlotsError, LoadContextError, OpenSessionError};

mod dl;

mod object;
pub use object::{EncryptError, GetKeyParametersError, Object, RsaSignMechanism, SignError};

mod session;
pub use session::{
    FindObjectsError, GenerateKeyPairError, GetKeyError, KeyPair, LoginError, PublicKey, Session,
};

#[derive(Clone, Debug, PartialEq)]
pub struct Uri {
    pub slot_identifier: UriSlotIdentifier,
    pub object_label: Option<String>,
    pub pin: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UriSlotIdentifier {
    Label(String),
    SlotId(pkcs11_sys::CK_SLOT_ID),
}

impl std::fmt::Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pkcs11:")?;

        match &self.slot_identifier {
            UriSlotIdentifier::Label(token_label) => {
                write!(f, "token=")?;
                let value = percent_encoding::utf8_percent_encode(
                    &*token_label,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                for s in value {
                    write!(f, "{}", s)?;
                }
            }

            UriSlotIdentifier::SlotId(slot_id) => {
                write!(f, "slot-id=")?;
                let slot_id = slot_id.0.to_string();
                let value = percent_encoding::utf8_percent_encode(
                    &slot_id,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                for s in value {
                    write!(f, "{}", s)?;
                }
            }
        }

        if let Some(object_label) = &self.object_label {
            write!(f, ";object=")?;
            let value = percent_encoding::utf8_percent_encode(
                &*object_label,
                percent_encoding::NON_ALPHANUMERIC,
            );
            for s in value {
                write!(f, "{}", s)?;
            }
        }

        if let Some(pin) = &self.pin {
            write!(f, "?pin-value=")?;
            let value =
                percent_encoding::utf8_percent_encode(&*pin, percent_encoding::NON_ALPHANUMERIC);
            for s in value {
                write!(f, "{}", s)?;
            }
        }

        Ok(())
    }
}

impl std::str::FromStr for Uri {
    type Err = ParsePkcs11UriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Ref https://tools.ietf.org/html/rfc7512#section-2.3
        //
        // Only object-label, slot-id, token-label and pin-value are parsed from the URL. If both slot-id and token are provided, token is ignored.

        enum PathComponentKey {
            Object,
            SlotId,
            Token,
        }

        enum QueryComponentKey {
            PinValue,
        }

        fn parse_key_value_pair<'a, F, T>(
            s: &'a str,
            mut key_discriminant: F,
        ) -> Result<Option<(T, std::borrow::Cow<'a, str>)>, ParsePkcs11UriError>
        where
            F: FnMut(&[u8]) -> Option<T>,
        {
            let mut parts = s.splitn(2, '=');

            let key = parts.next().expect("str::splitn() yields at least one str");
            let key = percent_encoding::percent_decode(key.as_bytes());
            let key: std::borrow::Cow<'a, _> = key.into();
            let typed_key = match key_discriminant(&*key) {
                Some(typed_key) => typed_key,
                None => return Ok(None),
            };

            let value = parts.next().unwrap_or_default();
            let value = percent_encoding::percent_decode(value.as_bytes());
            match value.decode_utf8() {
                Ok(value) => Ok(Some((typed_key, value))),
                Err(err) => Err(ParsePkcs11UriError::InvalidUtf8(
                    key.into_owned(),
                    err.into(),
                )),
            }
        }

        let mut object_label = None;
        let mut token_label = None;
        let mut slot_id = None;
        let mut pin = None;

        let s = if s.starts_with("pkcs11:") {
            &s[("pkcs11:".len())..]
        } else {
            return Err(ParsePkcs11UriError::InvalidScheme);
        };

        let mut url_parts = s.split('?');

        let path = url_parts
            .next()
            .expect("str::split() yields at least one str");
        let path_components = path.split(';');
        for path_component in path_components {
            let key_value_pair = parse_key_value_pair(path_component, |key| match key {
                b"object" => Some(PathComponentKey::Object),
                b"slot-id" => Some(PathComponentKey::SlotId),
                b"token" => Some(PathComponentKey::Token),
                _ => None,
            })?;
            if let Some((key, value)) = key_value_pair {
                match key {
                    PathComponentKey::Object => {
                        object_label = Some(value.into_owned());
                    }
                    PathComponentKey::SlotId => {
                        let value = value.parse::<pkcs11_sys::CK_SLOT_ID>().map_err(|err| {
                            ParsePkcs11UriError::MalformedSlotId(value.into_owned(), err)
                        })?;
                        slot_id = Some(value);
                    }
                    PathComponentKey::Token => {
                        token_label = Some(value.into_owned());
                    }
                }
            }
        }

        let query = url_parts.next().unwrap_or_default();
        let query_components = query.split('&');
        for query_component in query_components {
            let key_value_pair = parse_key_value_pair(query_component, |key| match key {
                b"pin-value" => Some(QueryComponentKey::PinValue),
                _ => None,
            })?;
            if let Some((key, value)) = key_value_pair {
                match key {
                    QueryComponentKey::PinValue => {
                        pin = Some(value.into_owned());
                    }
                }
            }
        }

        let slot_identifier = match (token_label, slot_id) {
            (_, Some(slot_id)) => UriSlotIdentifier::SlotId(slot_id),
            (Some(token_label), _) => UriSlotIdentifier::Label(token_label),
            (None, None) => return Err(ParsePkcs11UriError::NeitherSlotIdNorTokenSpecified),
        };

        Ok(Uri {
            slot_identifier,
            object_label,
            pin,
        })
    }
}

#[derive(Debug)]
pub enum ParsePkcs11UriError {
    InvalidScheme,
    InvalidUtf8(Vec<u8>, Box<dyn std::error::Error>),
    MalformedSlotId(String, <pkcs11_sys::CK_SLOT_ID as std::str::FromStr>::Err),
    NeitherSlotIdNorTokenSpecified,
}

impl std::fmt::Display for ParsePkcs11UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsePkcs11UriError::InvalidScheme => f.write_str("URI does not have pkcs11 scheme"),
            ParsePkcs11UriError::InvalidUtf8(key, _) => {
                write!(f, "URI component with key [{:?}] is not valid UTF-8", key)
            }
            ParsePkcs11UriError::MalformedSlotId(value, _) => write!(
                f,
                "pin-value path component has malformed value [{}]",
                value
            ),
            ParsePkcs11UriError::NeitherSlotIdNorTokenSpecified => {
                f.write_str("URI has neither [slot-id] nor [token] components")
            }
        }
    }
}

impl std::error::Error for ParsePkcs11UriError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            ParsePkcs11UriError::InvalidScheme => None,
            ParsePkcs11UriError::InvalidUtf8(_, inner) => Some(&**inner),
            ParsePkcs11UriError::MalformedSlotId(_, inner) => Some(inner),
            ParsePkcs11UriError::NeitherSlotIdNorTokenSpecified => None,
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Uri;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a PKCS#11 URI representing the base slot")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let value = value.parse().map_err(serde::de::Error::custom)?;
                Ok(value)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_pkcs11_uri() {
        for &slot_id in &[None, Some(1)] {
            for &token_label in &[None, Some("foo bar")] {
                for &object_label in &[None, Some("baz quux")] {
                    for &pin in &[None, Some("1234")] {
                        let mut path_components = vec![];

                        if let Some(slot_id) = slot_id {
                            path_components.push(format!("slot-id={}", slot_id));
                        }

                        if let Some(token_label) = token_label {
                            path_components.push(format!("token={}", token_label));
                        }

                        if let Some(object_label) = object_label {
                            path_components.push(format!("object={}", object_label));
                        }

                        let path_components_len = path_components.len();
                        for permutation in itertools::Itertools::permutations(
                            path_components.into_iter(),
                            path_components_len,
                        ) {
                            let mut uri_string = format!("pkcs11:{}", permutation.join(";"));

                            if let Some(pin) = pin {
                                use std::fmt::Write;
                                write!(uri_string, "?pin-value={}", pin).unwrap();
                            }

                            parse_pkcs11_uri_inner(
                                &uri_string,
                                slot_id,
                                token_label,
                                object_label,
                                pin,
                            );
                        }
                    }
                }
            }
        }

        let _ = "kcs11:token=Foo%20Bar"
            .parse::<super::Uri>()
            .expect_err("expect URI with invalid scheme to fail to parse");

        let _ = "pkcs11:"
            .parse::<super::Uri>()
            .expect_err("expect URI with neither label nor slot ID to fail to parse");
    }

    fn parse_pkcs11_uri_inner(
        uri_string: &str,
        slot_id: Option<pkcs11_sys::CK_ULONG>,
        token_label: Option<&str>,
        object_label: Option<&str>,
        pin: Option<&str>,
    ) {
        eprintln!("{}", uri_string);

        let uri: Result<super::Uri, _> = uri_string.parse();

        // Slot ID / token label validation
        match (slot_id, token_label, &uri) {
            // One of slot ID or token label is required
            (None, None, Err(_)) => return,

            // If slot ID is given, it is used, even if token label is given
            (
                Some(expected_slot_id),
                _,
                Ok(super::Uri {
                    slot_identifier:
                        super::UriSlotIdentifier::SlotId(pkcs11_sys::CK_SLOT_ID(actual_slot_id)),
                    ..
                }),
            ) => assert_eq!(expected_slot_id, *actual_slot_id),

            // If slot ID is not given and token label is, then token label is used
            (
                None,
                Some(expected_token_label),
                Ok(super::Uri {
                    slot_identifier: super::UriSlotIdentifier::Label(actual_token_label),
                    ..
                }),
            ) => assert_eq!(expected_token_label, actual_token_label),

            (slot_id, token_label, uri) => panic!(
                "test failure: slot_id: {:?}, token_label: {:?}, uri: {:?}",
                slot_id, token_label, uri
            ),
        }

        let uri = uri.unwrap_or_else(|err| {
            panic!(
                "URI {:?} ought to have been successfully parsed but failed with {:?}",
                uri_string, err
            )
        });

        match (object_label, &uri) {
            (
                Some(expected_object_label),
                super::Uri {
                    object_label: Some(actual_object_label),
                    ..
                },
            ) => assert_eq!(expected_object_label, actual_object_label),

            (
                None,
                super::Uri {
                    object_label: None, ..
                },
            ) => (),

            (object_label, uri) => panic!(
                "test failure: object_label: {:?}, uri: {:?}",
                object_label, uri
            ),
        }

        match (pin, &uri) {
            (
                Some(expected_pin),
                super::Uri {
                    pin: Some(actual_pin),
                    ..
                },
            ) => assert_eq!(expected_pin, actual_pin),

            (None, super::Uri { pin: None, .. }) => (),

            (pin, uri) => panic!("test failure: pin: {:?}, uri: {:?}", pin, uri),
        }
    }
}
