// Copyright (c) Microsoft. All rights reserved.

use crate::server::Response;

fn register(
    registration_id: String,
    headers: &std::collections::HashMap<String, String>,
    body: Option<String>,
    context: &mut crate::server::DpsContext,
) -> Response {
    let body = if let Some(body) = body {
        let body: aziot_dps_client_async::model::DeviceRegistration =
            match serde_json::from_str(&body) {
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

    // Unique value to use for both operation ID and device ID.
    let uuid = uuid::Uuid::new_v4().to_hyphenated().to_string();

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let mut registration_state = aziot_dps_client_async::model::DeviceRegistrationResult {
        tpm: None,
        x509: None,
        symmetric_key: None,
        registration_id: Some(registration_id),
        created_date_time_utc: Some(now.clone()),
        // Use localhost as hubname so devices provisioned with mock-dps-server don't try to
        // communicate with IoT Hub.
        assigned_hub: Some("localhost".to_string()),
        device_id: Some(uuid.clone()),
        status: Some("assigned".to_string()),
        substatus: Some("initialAssignment".to_string()),
        error_code: None,
        error_message: None,
        last_updated_date_time_utc: Some(now),
        etag: Some("mock-dps-etag".to_string()),
    };

    if body.tpm.is_some() {
        registration_state.tpm = Some(aziot_dps_client_async::model::TpmRegistrationResult {
            authentication_key: "mock-dps-tpm-key".to_string(),
        });
    } else if headers.get("authorization").is_some() {
        registration_state.symmetric_key = Some(
            aziot_dps_client_async::model::SymmetricKeyRegistrationResult {
                enrollment_group_id: Some("mock-dps-enrollment-group".to_string()),
            },
        );
    } else {
        registration_state.x509 = Some(aziot_dps_client_async::model::X509RegistrationResult {
            certificate_info: None,
            enrollment_group_id: Some("mock-dps-enrollment-group".to_string()),
            signing_certificate_info: None,
        });
    };

    let operation_id = {
        let registration = aziot_dps_client_async::model::RegistrationOperationStatus {
            operation_id: uuid.clone(),
            status: "assigned".to_string(),
            registration_state: Some(registration_state),
        };

        let mut context = context.lock().unwrap();
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

fn operation_status(operation_id: &str, context: &mut crate::server::DpsContext) -> Response {
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

pub(crate) fn process_dps_request(
    req: crate::server::ParsedRequest,
    context: &mut crate::server::DpsContext,
) -> Response {
    lazy_static::lazy_static! {
        static ref DPS_REGEX: regex::Regex = regex::Regex::new(
            "/(?P<scopeId>[^/]+)/registrations/(?P<registrationId>[^/]+)/(?P<action>.+)\\?api-version=\\d{4}-\\d{2}-\\d{2}$"
        ).unwrap();

        static ref OPERATION_STATUS_REGEX: regex::Regex = regex::Regex::new(
            "operations/(?P<operationId>[^/]+)$"
        ).unwrap();
    }

    if !DPS_REGEX.is_match(&req.uri) {
        return Response::not_found(format!("{} not found", req.uri));
    }

    let captures = DPS_REGEX.captures(&req.uri).unwrap();

    let registration_id = match get_param(&captures, "registrationId") {
        Ok(registration_id) => registration_id,
        Err(response) => return response,
    };

    let action = match get_param(&captures, "action") {
        Ok(action) => action,
        Err(response) => return response,
    };

    if OPERATION_STATUS_REGEX.is_match(&action) {
        if req.method != hyper::Method::GET {
            return Response::method_not_allowed(&req.method);
        }

        let captures = OPERATION_STATUS_REGEX.captures(&action).unwrap();
        let operation_id = match get_param(&captures, "operationId") {
            Ok(operation_id) => operation_id,
            Err(response) => return response,
        };

        operation_status(&operation_id, context)
    } else if action == "register" {
        if req.method != hyper::Method::PUT {
            return Response::method_not_allowed(&req.method);
        }

        register(registration_id, &req.headers, req.body, context)
    } else {
        Response::not_found(format!("{} not found", req.uri))
    }
}
