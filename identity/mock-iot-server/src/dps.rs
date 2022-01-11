// Copyright (c) Microsoft. All rights reserved.

use crate::server::Response;

#[allow(clippy::too_many_lines)]
fn register(
    registration_id: String,
    headers: &std::collections::HashMap<String, String>,
    body: &Option<String>,
    context: &mut crate::server::Context,
) -> Response {
    let body = if let Some(body) = body {
        let body: aziot_dps_client_async::model::DeviceRegistration =
            match serde_json::from_str(body) {
                Ok(body) => body,
                Err(_) => return Response::bad_request("failed to parse register body"),
            };

        if let Some(req_reg_id) = &body.registration_id {
            if req_reg_id != &registration_id {
                return Response::bad_request("registration IDs in URI and request mismatch");
            }
        }

        body
    } else {
        return Response::bad_request("missing required body for register");
    };

    let mut context = context.lock().unwrap();

    // Unique value to use for both operation ID and device ID.
    let uuid = uuid::Uuid::new_v4().to_hyphenated().to_string();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

    let mut registration_state = aziot_dps_client_async::model::DeviceRegistrationResult {
        tpm: None,
        x509: None,
        symmetric_key: None,
        registration_id: Some(registration_id),
        created_date_time_utc: Some(now.clone()),
        // Use localhost as hubname so devices provisioned with mock-iot-server don't try to
        // communicate with IoT Hub.
        assigned_hub: Some(context.endpoint.clone()),
        device_id: Some(uuid.clone()),
        status: Some("assigned".to_string()),
        substatus: Some("initialAssignment".to_string()),
        error_code: None,
        error_message: None,
        last_updated_date_time_utc: Some(now),
        etag: Some("mock-iot-etag".to_string()),
        trust_bundle: context.trust_bundle.clone(),
        identity_cert: None,
        certificate_issuance_policy: None,
    };

    if body.tpm.is_some() {
        registration_state.tpm = Some(aziot_dps_client_async::model::TpmRegistrationResult {
            authentication_key: "mock-iot-tpm-key".to_string(),
        });
    } else if headers.get("authorization").is_some() {
        registration_state.symmetric_key = Some(
            aziot_dps_client_async::model::SymmetricKeyRegistrationResult {
                enrollment_group_id: Some("mock-iot-enrollment-group".to_string()),
            },
        );
    } else {
        registration_state.x509 = Some(aziot_dps_client_async::model::X509RegistrationResult {
            certificate_info: None,
            enrollment_group_id: Some("mock-iot-enrollment-group".to_string()),
            signing_certificate_info: None,
        });
    };

    if context.enable_server_certs {
        registration_state.certificate_issuance_policy =
            Some(aziot_identity_common::CertIssuancePolicy {
                end_point: context.endpoint.clone(),
                certificate_issuance_type:
                    aziot_identity_common::CertIssuanceType::ServerCertificate,
                key_length_in_bits: 2048,
                key_curve: None,
            });
    }

    match (body.client_cert_csr, context.enable_identity_certs) {
        // Issue an identity certificate from the provided CSR.
        (Some(csr), true) => {
            let client_cert_csr = match base64::decode(csr) {
                Ok(csr) => csr,
                Err(_) => return Response::bad_request("bad client cert csr"),
            };

            let client_cert_csr = match openssl::x509::X509Req::from_der(&client_cert_csr) {
                Ok(csr) => csr,
                Err(_) => return Response::bad_request("bad client cert csr"),
            };

            registration_state.identity_cert =
                Some(crate::certs::issuance::issue_cert(&client_cert_csr));
        }

        // DPS returns a specific error when a CSR is provided but identity certificates
        // aren't enabled.
        (Some(_), false) => {
            registration_state.tpm = None;
            registration_state.x509 = None;
            registration_state.symmetric_key = None;
            registration_state.assigned_hub = None;
            registration_state.device_id = None;
            registration_state.status = Some("failed".to_string());
            registration_state.substatus = None;
            registration_state.error_code = Some(400_000);
            registration_state.error_message =
                Some("Device sent CSR but it is not configured in the service.".to_string());
            registration_state.trust_bundle = None;
        }

        // Don't issue identity certificate if no CSR is provided.
        (None, _) => {}
    }

    let operation_id = {
        let registration = aziot_dps_client_async::model::RegistrationOperationStatus {
            operation_id: uuid.clone(),
            status: registration_state.status.clone().unwrap(),
            registration_state: Some(registration_state),
        };

        context
            .in_progress_operations
            .insert(uuid.clone(), registration);

        uuid
    };

    let response = aziot_dps_client_async::model::RegistrationOperationStatus {
        operation_id,
        status: "assigning".to_string(),
        registration_state: None,
    };

    Response::json(hyper::StatusCode::OK, response)
}

fn operation_status(operation_id: &str, context: &mut crate::server::Context) -> Response {
    let mut context = context.lock().unwrap();

    match context.in_progress_operations.remove(operation_id) {
        Some(operation) => Response::json(hyper::StatusCode::OK, operation),
        None => Response::not_found(format!("operation {} not found", operation_id)),
    }
}

fn get_param(captures: &regex::Captures<'_>, name: &str) -> Result<String, Response> {
    let value = &captures[name];

    let value = percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| Response::bad_request(format!("bad {}", name)))?
        .to_string();

    Ok(value)
}

pub(crate) fn process_request(
    req: &crate::server::ParsedRequest,
    context: &mut crate::server::Context,
) -> Option<Response> {
    lazy_static::lazy_static! {
        static ref DPS_REGEX: regex::Regex = regex::Regex::new(
            "/(?P<scopeId>[^/]+)/registrations/(?P<registrationId>[^/]+)/(?P<action>.+)\\?api-version="
        ).unwrap();

        static ref OPERATION_STATUS_REGEX: regex::Regex = regex::Regex::new(
            "operations/(?P<operationId>[^/]+)$"
        ).unwrap();
    }

    if !DPS_REGEX.is_match(&req.uri) {
        return None;
    }

    let captures = DPS_REGEX.captures(&req.uri).unwrap();

    let registration_id = match get_param(&captures, "registrationId") {
        Ok(registration_id) => registration_id,
        Err(response) => return Some(response),
    };

    let action = match get_param(&captures, "action") {
        Ok(action) => action,
        Err(response) => return Some(response),
    };

    if OPERATION_STATUS_REGEX.is_match(&action) {
        if req.method != hyper::Method::GET {
            return Some(Response::method_not_allowed(&req.method));
        }

        let captures = OPERATION_STATUS_REGEX.captures(&action).unwrap();
        let operation_id = match get_param(&captures, "operationId") {
            Ok(operation_id) => operation_id,
            Err(response) => return Some(response),
        };

        Some(operation_status(&operation_id, context))
    } else if action == "register" {
        if req.method != hyper::Method::PUT {
            return Some(Response::method_not_allowed(&req.method));
        }

        Some(register(registration_id, &req.headers, &req.body, context))
    } else {
        Some(Response::not_found(format!("{} not found", req.uri)))
    }
}
