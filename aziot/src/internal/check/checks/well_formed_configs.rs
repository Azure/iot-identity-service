use super::prelude::*;

#[derive(Serialize)]
pub struct WellFormedConfigs {}

impl WellFormedConfigs {
    pub fn new() -> WellFormedConfigs {
        WellFormedConfigs {}
    }
}

#[async_trait::async_trait]
impl Checker for WellFormedConfigs {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "config-tomls-well-formed",
            description: "config toml files are well-formed",
        }
    }

    async fn execute(&mut self, _cfg: &CheckerCfg, _shared: &mut CheckerCache) -> CheckResult {
        CheckResult::Warning(match std::fs::read("bruhhh") {
            Ok(_) => unimplemented!(),
            Err(e) => Error::new(e).context("foo").context("bar"),
        })
    }
}
