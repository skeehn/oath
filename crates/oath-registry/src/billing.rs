use anyhow::{Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;

#[derive(Clone)]
pub struct StripeBilling {
    client: reqwest::Client,
    secret_key: String,
    webhook_secret: String,
}

impl StripeBilling {
    pub fn new(secret_key: String, webhook_secret: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            secret_key,
            webhook_secret,
        }
    }
    pub async fn create_checkout(
        &self,
        organization: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<String> {
        let response: Value = self
            .client
            .post("https://api.stripe.com/v1/checkout/sessions")
            .bearer_auth(&self.secret_key)
            .form(&[
                ("mode", "subscription"),
                ("line_items[0][price]", price_id),
                ("line_items[0][quantity]", "1"),
                ("success_url", success_url),
                ("cancel_url", cancel_url),
                ("client_reference_id", organization),
                ("metadata[organization]", organization),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        response
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .context("Stripe checkout response has no URL")
    }
    pub fn verify_webhook(&self, header: &str, body: &[u8], now: u64) -> Result<Value> {
        let mut timestamp = None;
        let mut signatures = Vec::new();
        for part in header.split(',') {
            if let Some(v) = part.strip_prefix("t=") {
                timestamp = v.parse::<u64>().ok();
            }
            if let Some(v) = part.strip_prefix("v1=") {
                signatures.push(v);
            }
        }
        let timestamp = timestamp.context("Stripe signature has no timestamp")?;
        anyhow::ensure!(
            now.abs_diff(timestamp) <= 300,
            "Stripe webhook timestamp is outside tolerance"
        );
        let valid = signatures.into_iter().any(|value| {
            let Ok(candidate) = hex::decode(value) else {
                return false;
            };
            let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(self.webhook_secret.as_bytes()) else {
                return false;
            };
            mac.update(timestamp.to_string().as_bytes());
            mac.update(b".");
            mac.update(body);
            mac.verify_slice(&candidate).is_ok()
        });
        anyhow::ensure!(valid, "invalid Stripe webhook signature");
        Ok(serde_json::from_slice(body)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsigned_webhooks() {
        let billing = StripeBilling::new("sk".into(), "whsec".into());
        assert!(billing.verify_webhook("t=1,v1=00", b"{}", 1).is_err());
    }

    #[test]
    fn accepts_valid_current_signature_and_rejects_expired_signature() {
        let billing = StripeBilling::new("sk".into(), "whsec".into());
        let body = br#"{"id":"evt_1","type":"test"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec").unwrap();
        mac.update(b"1000.");
        mac.update(body);
        let signature = hex::encode(mac.finalize().into_bytes());
        let header = format!("t=1000,v1={signature}");
        assert_eq!(
            billing.verify_webhook(&header, body, 1000).unwrap()["id"],
            "evt_1"
        );
        assert!(billing.verify_webhook(&header, body, 1301).is_err());
    }
}
