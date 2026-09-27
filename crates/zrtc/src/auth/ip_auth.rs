//! IP peering: no SIP-level credentials at all. The provider authenticates
//! us by source address; we do the same for them. Requests carry no
//! Authorization headers and no REGISTER is needed.

use sip_core::message::Method;

use super::{ChallengeOutcome, KeepaliveCtx, TrunkAuth};

/// No-op authenticator for IP-peered trunks.
pub struct IpAuth;

impl TrunkAuth for IpAuth {
    fn mode(&self) -> &'static str {
        "ip"
    }

    fn sign_request(&self, _method: Method, _uri: &str, _headers: &mut Vec<(String, String)>) {
        // IP peering: no auth headers.
    }

    fn on_challenge(
        &mut self,
        status: u16,
        _www: Option<&str>,
        _proxy: Option<&str>,
    ) -> ChallengeOutcome {
        // There is no credential we can produce: the vendor rejected our
        // source address (or expects a different mode entirely).
        ChallengeOutcome::Fail(format!(
            "ip peering has no SIP credentials; vendor replied {status} (check source ACLs or the configured auth mode)"
        ))
    }

    fn pending_header(&self) -> Option<(String, String)> {
        None
    }

    fn on_keepalive(&mut self, _ctx: &mut KeepaliveCtx) {
        // Plain OPTIONS; the keepalive driver sends it.
    }
}
