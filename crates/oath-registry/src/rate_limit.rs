use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use redis::AsyncCommands;

use crate::control_plane::PostgresControlPlane;

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn consume(
        &self,
        subject: &str,
        bucket: &str,
        maximum: i64,
        window_seconds: i64,
    ) -> Result<bool>;
    async fn ready(&self) -> Result<()>;
    async fn prune(&self, _cutoff: i64) -> Result<u64> {
        Ok(0)
    }
    fn backend(&self) -> &'static str;
}

pub type SharedRateLimiter = Arc<dyn RateLimiter>;

pub struct PostgresRateLimiter {
    control: PostgresControlPlane,
}

impl PostgresRateLimiter {
    pub fn new(control: PostgresControlPlane) -> Self {
        Self { control }
    }
}

#[async_trait]
impl RateLimiter for PostgresRateLimiter {
    async fn consume(
        &self,
        subject: &str,
        bucket: &str,
        maximum: i64,
        window: i64,
    ) -> Result<bool> {
        self.control
            .consume_rate_limit(subject, bucket, maximum, window)
            .await
    }

    async fn ready(&self) -> Result<()> {
        self.control.ready().await
    }

    async fn prune(&self, cutoff: i64) -> Result<u64> {
        self.control.prune_rate_limits_before(cutoff).await
    }

    fn backend(&self) -> &'static str {
        "postgres"
    }
}

pub struct RedisRateLimiter {
    client: redis::Client,
    prefix: String,
}

impl RedisRateLimiter {
    pub fn connect(url: &str) -> Result<Self> {
        Ok(Self {
            client: redis::Client::open(url).context("parse REDIS_URL")?,
            prefix: std::env::var("OATH_REGISTRY_REDIS_PREFIX")
                .unwrap_or_else(|_| "oath:rate-limit".into()),
        })
    }
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn consume(
        &self,
        subject: &str,
        bucket: &str,
        maximum: i64,
        window: i64,
    ) -> Result<bool> {
        let now = crate::now() as i64;
        let window_start = now - now.rem_euclid(window);
        let key = format!("{}:{}:{}:{}", self.prefix, bucket, subject, window_start);
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let count: i64 = connection.incr(&key, 1_i64).await?;
        if count == 1 {
            let _: bool = connection.expire(&key, window.saturating_add(5)).await?;
        }
        Ok(count <= maximum)
    }

    async fn ready(&self) -> Result<()> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let pong: String = redis::cmd("PING").query_async(&mut connection).await?;
        anyhow::ensure!(pong == "PONG", "Redis readiness returned {pong}");
        Ok(())
    }

    fn backend(&self) -> &'static str {
        "redis"
    }
}

pub fn rate_limiter_from_env(control: PostgresControlPlane) -> Result<SharedRateLimiter> {
    match std::env::var("OATH_REGISTRY_RATE_LIMIT_BACKEND")
        .unwrap_or_else(|_| "postgres".into())
        .as_str()
    {
        "postgres" => Ok(Arc::new(PostgresRateLimiter::new(control))),
        "redis" => {
            let url = std::env::var("REDIS_URL")
                .context("REDIS_URL is required for Redis rate limiting")?;
            Ok(Arc::new(RedisRateLimiter::connect(&url)?))
        }
        value => anyhow::bail!("unsupported OATH_REGISTRY_RATE_LIMIT_BACKEND `{value}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn live_redis_enforces_the_same_limit_boundary() {
        let Ok(url) = std::env::var("OATH_TEST_REDIS_URL") else {
            return;
        };
        let limiter = RedisRateLimiter::connect(&url).unwrap();
        let subject = format!("test-{}", crate::now());
        assert!(limiter.consume(&subject, "parity", 2, 60).await.unwrap());
        assert!(limiter.consume(&subject, "parity", 2, 60).await.unwrap());
        assert!(!limiter.consume(&subject, "parity", 2, 60).await.unwrap());
        limiter.ready().await.unwrap();
    }
}
