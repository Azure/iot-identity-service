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

    async fn execute(&mut self, _cfg: &CheckerCfg, _shared: &mut CheckerCache) -> CheckResult {
        tokio::time::delay_for(std::time::Duration::from_millis(1000)).await;
        CheckResult::Warning("aight".into())
    }
}
