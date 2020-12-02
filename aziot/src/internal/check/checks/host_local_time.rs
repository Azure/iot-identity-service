use super::prelude::*;

#[derive(Serialize, Default)]
pub struct HostLocalTime {
    offset: Option<i64>,
}

#[async_trait::async_trait]
impl Checker for HostLocalTime {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "host-local-time",
            description: "host time is close to reference time",
        }
    }

    async fn execute(&mut self, checker_cfg: &CheckerCfg, cache: &mut CheckerCache) -> CheckResult {
        self.execute_inner(checker_cfg, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl HostLocalTime {
    async fn execute_inner(
        &mut self,
        checker_cfg: &CheckerCfg,
        _cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        // TODO: check against parent time in nested edge scenarios

        fn is_server_unreachable_error(err: &mini_sntp::Error) -> bool {
            match err {
                mini_sntp::Error::ResolveNtpPoolHostname(_) => true,
                mini_sntp::Error::SendClientRequest(err)
                | mini_sntp::Error::ReceiveServerResponse(err) => {
                    err.kind() == std::io::ErrorKind::TimedOut || // Windows
                    err.kind() == std::io::ErrorKind::WouldBlock // Unix
                }
                _ => false,
            }
        }

        let mini_sntp::SntpTimeQueryResult {
            local_clock_offset, ..
        } = match mini_sntp::query(&checker_cfg.ntp_server) {
            Ok(result) => result,
            Err(err) => {
                if is_server_unreachable_error(&err) {
                    return Ok(CheckResult::Warning(
                        Error::new(err).context("Could not query NTP server"),
                    ));
                } else {
                    return Err(err).context("Could not query NTP server");
                }
            }
        };

        let offset = local_clock_offset.num_seconds().abs();
        self.offset = Some(offset);
        if offset >= 10 {
            return Ok(CheckResult::Warning(anyhow!(
                "Time on the device is out of sync with the NTP server. This may cause problems connecting to IoT Hub.\n\
                 Please ensure time on device is accurate, for example by installing an NTP daemon.",
            )));
        }

        Ok(CheckResult::Ok)
    }
}
