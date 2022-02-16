// Copyright (c) Microsoft. All rights reserved.

use crate::server::Response;

fn list_modules(
    modules: &std::collections::HashSet<aziot_identity_common::hub::Module>,
) -> Response {
    let mut response = vec![];

    for module in modules {
        response.push(module.clone());
    }

    Response::json(hyper::StatusCode::OK, response)
}

fn module_action(
    method: &hyper::Method,
    _module_id: &str,
    _modules: &mut std::collections::HashSet<aziot_identity_common::hub::Module>,
) -> Response {
    // Current tests do not require these to be implemented, but they may be
    // needed in the future.
    #[allow(clippy::match_same_arms)]
    match *method {
        hyper::Method::DELETE => unimplemented!(),
        hyper::Method::GET => unimplemented!(),
        hyper::Method::POST => unimplemented!(),
        hyper::Method::PUT => unimplemented!(),
        _ => Response::method_not_allowed(method),
    }
}

pub(crate) fn process_request(
    req: &crate::server::ParsedRequest,
    context: &mut crate::server::Context,
) -> Option<Response> {
    lazy_static::lazy_static! {
        static ref DEVICES_REGEX: regex::Regex = regex::Regex::new(
            "/devices/(?P<deviceId>[^/]+)/(?P<action>.+)\\?api-version="
        ).unwrap();

        static ref MODULE_REGEX: regex::Regex = regex::Regex::new(
            "modules/(?P<moduleId>[^/]+)$"
        ).unwrap();
    }

    if !DEVICES_REGEX.is_match(&req.uri) {
        return None;
    }

    let captures = DEVICES_REGEX.captures(&req.uri).unwrap();

    let device_id = match crate::server::get_param(&captures, "deviceId") {
        Ok(device_id) => device_id,
        Err(response) => return Some(response),
    };

    let action = match crate::server::get_param(&captures, "action") {
        Ok(action) => action,
        Err(response) => return Some(response),
    };

    let mut context = context.lock().unwrap();

    let modules = match context.devices.get_mut(&device_id) {
        Some(modules) => modules,
        None => return None,
    };

    if MODULE_REGEX.is_match(&action) {
        let captures = MODULE_REGEX.captures(&action).unwrap();
        let module_id = match crate::server::get_param(&captures, "moduleId") {
            Ok(module_id) => module_id,
            Err(response) => return Some(response),
        };

        Some(module_action(&req.method, &module_id, modules))
    } else if action == "modules" {
        Some(list_modules(modules))
    } else {
        None
    }
}
