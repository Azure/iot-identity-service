use super::Checker;

mod prelude {
    pub use anyhow::{Context, Error, Result};
    pub use serde::Serialize;

    pub use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerCfg, CheckerMeta};
}

mod well_formed_configs;

pub fn all_checks() -> Vec<(&'static str, Vec<Box<dyn Checker>>)> {
    // DEVNOTE: keep ordering consistent. Later tests may depend on earlier tests.
    vec![
        ("Configuration checks", {
            let mut v: Vec<Box<dyn Checker>> = Vec::new();
            v.push(Box::new(well_formed_configs::WellFormedConfigs::new()));
            v
        }),
        ("Connectivity checks", vec![]),
    ]
}
