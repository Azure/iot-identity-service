// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::let_unit_value,
    clippy::type_complexity,
)]

mod http;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await?;

    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let settings = read_is_settings()?;
    let (_pmap, _mset) =  convert_to_map(&settings.principal);

    let authenticator = Box::new(|_| Ok(aziot_identityd::auth::AuthId::Unknown));

    // TODO: Enable SettingsAuthorizer once Unix Domain Sockets is ported over.
    // let authorizer = aziot_identityd::SettingsAuthorizer { pmap };
    // let authorizer = Box::new(authorizer);
    let authorizer = Box::new(|_| {Ok(true)});

    let server = aziot_identityd::Server::new(authenticator,authorizer)?;
    let server = std::sync::Arc::new(server);

    log::info!("Identity Service starting..");

    let incoming = hyper::server::conn::AddrIncoming::bind(&"0.0.0.0:8901".parse()?)?;

    let server =
        hyper::Server::builder(incoming)
            .serve(hyper::service::make_service_fn(|_| {
                let server = http::Server { inner: server.clone() };
                futures_util::future::ok::<_, std::convert::Infallible>(server)
            }));
    let () = server.await?;

    log::info!("Identity Service stopped.");

    Ok(())
}

fn read_is_settings() -> Result<aziot_identityd::settings::Settings, Box<dyn std::error::Error>> {
    let settings = aziot_identityd::app::init()?;
    Ok(settings)
}

fn convert_to_map(principal: &Option<Vec<aziot_identityd::settings::Principal>>)
    -> (std::collections::BTreeMap<aziot_identityd::auth::Uid, aziot_identityd::settings::Principal>,
        std::collections::BTreeSet<aziot_identity_common::ModuleId>)
{
    let mut pmap = std::collections::BTreeMap::new();
    let mut mset = std::collections::BTreeSet::new();

    if let Some(v) = principal.as_ref() { v.iter()
            .for_each(|p| {
                let p1 = p.clone();
                let p2 = p.clone();
                pmap.insert(p.uid, p1);
                mset.insert(p2.name);
            })};

    (pmap, mset)
}

#[cfg(test)]
mod tests {
    use aziot_identityd::auth::{Operation, OperationType, AuthId, Uid};
    use aziot_identityd::SettingsAuthorizer;
    use aziot_identityd::settings::{Principal, Settings};
    use crate::convert_to_map;
    use aziot_identityd::auth::authorization::Authorizer;
    use aziot_identity_common::{IdType, ModuleId};
    use std::path::Path;

    #[test]
    fn convert_to_map_creates_principal_lookup() {
        let p: Principal = Principal{uid: Uid(1001), name: ModuleId(String::from("module1")), id_type: Some(IdType::Module)};
        let (map, _) = convert_to_map(&Some(Vec::from([p.clone()])));

        assert!(map.contains_key(&Uid(1001)));
        assert_eq!(map.get(&Uid(1001)).unwrap(), &p);
    }

    #[test]
    fn settings_test() {
        let settings = Settings::new(Path::new("test/good_auth_settings.toml")).unwrap();

        let (map, _) = convert_to_map(&settings.principal);
        assert_eq!(map.len(), 3);
        assert!(map.contains_key(&Uid(1003)));
        assert_eq!(map.get(&Uid(1003)).unwrap().uid, Uid(1003));
        assert_eq!(map.get(&Uid(1003)).unwrap().name, ModuleId(String::from("hostprocess2")));
        assert_eq!(map.get(&Uid(1003)).unwrap().id_type, Some(IdType::Module));
    }

    #[test]
    fn empty_auth_settings_deny_any_action() {
        let (pmap, mset) = convert_to_map(&None);
        let auth = SettingsAuthorizer {pmap, mset};
        let operation = Operation { auth_id: AuthId::Unknown, op_type: OperationType::CreateModule(String::default()) };

        let res = auth.authorize(operation);

        match res {
            Ok(false) => (),
            _ => panic!("incorrect authorization returned"),
        }
    }
}
