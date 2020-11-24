use super::Checker;

mod prelude {
    pub use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerCfg, CheckerMeta};
    pub use serde::Serialize;
}

mod dummy;

pub fn all_checks() -> Vec<(&'static str, Vec<Box<dyn Checker>>)> {
    // DEVNOTE: keep ordering consistent. Later tests may depend on earlier tests.
    vec![
        ("Configuration checks", {
            let mut v: Vec<Box<dyn Checker>> = Vec::new();
            v.push(Box::new(dummy::Dummy::new("Ayy")));
            v.push(Box::new(dummy::Dummy::new("Bee")));
            v
        }),
        ("Connectivity checks", vec![]),
    ]
}
