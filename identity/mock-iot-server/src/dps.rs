// Copyright (c) Microsoft. All rights reserved.

use crate::server::Response;

#[allow(clippy::too_many_lines)]
fn register(
    registration_id: &str,
    body: Option<&String>,
    context: &mut crate::server::Context,
) -> Response {
    let body = if let Some(body) = body {
        let body: serde_json::value::Value = match serde_json::from_str(body) {
            Ok(body) => body,
            Err(_) => return Response::bad_request("failed to parse register body"),
        };

        if body["registrationId"] != registration_id {
            return Response::bad_request("registration IDs in URI and request mismatch");
        }

        body
    } else {
        return Response::bad_request("missing required body for register");
    };

    let mut context = context.lock().unwrap();

    // Unique value to use for both operation ID and device ID.
    let uuid = uuid::Uuid::new_v4().hyphenated().to_string();

    let tpm = if body["tpm"] == serde_json::value::Value::Null {
        None
    } else {
        Some(aziot_cloud_client_async::DpsResponse::TpmAuthKey {
            authentication_key: "mock-dps-tpm-key".to_string(),
        })
    };

    let payload = if body["payload"] == serde_json::value::Value::Null {
        None
    } else {
        match serde_json::to_value(WebhookResponsePayload {
            msg: "custom allocation payload received".to_string(),
            request_payload: body["payload"].clone(),
        }) {
            Ok(payload) => Some(payload),
            Err(_) => {
                return Response::Error {
                    status: http::StatusCode::INTERNAL_SERVER_ERROR,
                    message: "error creating webhook response payload".to_owned(),
                }
            }
        }
    };

    let registration = aziot_cloud_client_async::DpsResponse::DeviceRegistration::Assigned {
        tpm,
        device: aziot_cloud_client_async::dps::schema::Device {
            // Direct all Hub requests to be handled by this process's endpoint.
            assigned_hub: context.endpoint.clone(),
            device_id: uuid.clone(),
            payload,
        },
    };
    let operation_id = {
        context
            .in_progress_operations
            .insert(uuid.clone(), registration);

        uuid
    };

    let response = aziot_cloud_client_async::DpsResponse::OperationStatus { operation_id };

    Response::json(hyper::StatusCode::ACCEPTED, response)
}

fn operation_status(operation_id: &str, context: &mut crate::server::Context) -> Response {
    let mut context = context.lock().unwrap();

    let operation = if let Some(operation) = context.in_progress_operations.remove(operation_id) {
        operation
    } else {
        return Response::not_found(format!("operation {} not found", operation_id));
    };

    // Add new device with empty module set for successful registrations.
    if let aziot_cloud_client_async::DpsResponse::DeviceRegistration::Assigned { device, .. } =
        &operation
    {
        let device_id = device.device_id.clone();

        context
            .devices
            .insert(device_id, std::collections::HashSet::new());
    }

    Response::json(hyper::StatusCode::OK, operation)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WebhookResponsePayload {
    msg: String,
    request_payload: serde_json::value::Value,
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

    let registration_id = match crate::server::get_param(&captures, "registrationId") {
        Ok(registration_id) => registration_id,
        Err(response) => return Some(response),
    };

    let action = match crate::server::get_param(&captures, "action") {
        Ok(action) => action,
        Err(response) => return Some(response),
    };

    if OPERATION_STATUS_REGEX.is_match(&action) {
        if req.method != hyper::Method::GET {
            return Some(Response::method_not_allowed(&req.method));
        }

        let captures = OPERATION_STATUS_REGEX.captures(&action).unwrap();
        let operation_id = match crate::server::get_param(&captures, "operationId") {
            Ok(operation_id) => operation_id,
            Err(response) => return Some(response),
        };

        Some(operation_status(&operation_id, context))
    } else if action == "register" {
        if req.method != hyper::Method::PUT {
            return Some(Response::method_not_allowed(&req.method));
        }

        Some(register(&registration_id, req.body.as_ref(), context))
    } else {
        Some(Response::not_found(format!("{} not found", req.uri)))
    }
}
