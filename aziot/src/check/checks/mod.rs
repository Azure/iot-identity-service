mod prelude {
    pub(super) use crate::check::{CheckCfg, CheckResult, Checker, CheckerCache, CheckerMeta};
    pub use serde::Serialize;
}

mod dummy {
    use super::prelude::*;

    #[derive(Serialize)]
    pub struct Dummy {
        id: &'static str,
    }

    impl Dummy {
        pub fn new(id: &'static str) -> Dummy {
            Dummy { id }
        }
    }

    #[async_trait::async_trait]
    impl Checker for Dummy {
        fn meta(&self) -> CheckerMeta {
            CheckerMeta {
                id: self.id,
                description: "dummy",
            }
        }

        async fn execute(&mut self, _cfg: &CheckCfg, _shared: &mut CheckerCache) -> CheckResult {
            CheckResult::Warning("aight".into())
        }
    }
}

use super::Checker;

pub(super) fn all_checks() -> Vec<(&'static str, Vec<Box<dyn Checker>>)> {
    // DEVNOTE: keep ordering consistent. Later tests may depend on earlier tests.
    vec![
        ("Configuration checks", {
            let mut v: Vec<Box<dyn Checker>> = Vec::new();
            v.push(Box::new(dummy::Dummy::new("A")));
            v.push(Box::new(dummy::Dummy::new("B")));
            v
        }),
        ("Connectivity checks", vec![]),
    ]
}
