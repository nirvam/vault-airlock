use async_trait::async_trait;
use serde::Serialize;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize)]
pub struct HookContext {
    pub client_uid: Option<u32>,
    pub method: String,
    pub path: String,
    pub entry_title: Option<String>,
}

#[async_trait]
pub trait PreHook: Send + Sync {
    async fn run(&self, ctx: &HookContext) -> Result<(), String>;
}

#[async_trait]
pub trait PostHook: Send + Sync {
    async fn run(&self, ctx: &HookContext);
}

pub struct LoggingPreHook;

#[async_trait]
impl PreHook for LoggingPreHook {
    async fn run(&self, ctx: &HookContext) -> Result<(), String> {
        info!(
            "Access attempt: UID={:?}, Method={}, Path={}",
            ctx.client_uid, ctx.method, ctx.path
        );
        Ok(())
    }
}

pub struct FeishuPostHook {
    pub webhook_url: String,
}

#[async_trait]
impl PostHook for FeishuPostHook {
    async fn run(&self, ctx: &HookContext) {
        if let Some(ref title) = ctx.entry_title {
            info!("Sending Feishu notification for entry: {}", title);
            let client = reqwest::Client::new();
            let message = serde_json::json!({
                "msg_type": "text",
                "content": {
                    "text": format!("Vault access notification:\nEntry: {}\nUID: {:?}\nPath: {}", title, ctx.client_uid, ctx.path)
                }
            });

            if let Err(e) = client.post(&self.webhook_url).json(&message).send().await {
                warn!("Failed to send Feishu notification: {}", e);
            }
        }
    }
}

pub struct HookRegistry {
    pub pre_hooks: Vec<Arc<dyn PreHook>>,
    pub post_hooks: Vec<Arc<dyn PostHook>>,
}

impl HookRegistry {
    pub fn new() -> Self {
        Self {
            pre_hooks: vec![Arc::new(LoggingPreHook)],
            post_hooks: Vec::new(),
        }
    }

    pub fn add_post_hook(&mut self, hook: Arc<dyn PostHook>) {
        self.post_hooks.push(hook);
    }

    pub async fn run_pre(&self, ctx: &HookContext) -> Result<(), String> {
        for hook in &self.pre_hooks {
            hook.run(ctx).await?;
        }
        Ok(())
    }

    pub async fn run_post(&self, ctx: &HookContext) {
        for hook in &self.post_hooks {
            hook.run(ctx).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockPreHook {
        should_fail: bool,
    }

    #[async_trait]
    impl PreHook for MockPreHook {
        async fn run(&self, _ctx: &HookContext) -> Result<(), String> {
            if self.should_fail {
                Err("Rejected by mock".to_string())
            } else {
                Ok(())
            }
        }
    }

    struct MockPostHook {
        called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl PostHook for MockPostHook {
        async fn run(&self, _ctx: &HookContext) {
            self.called.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn test_hook_registry_new() {
        let registry = HookRegistry::new();
        assert_eq!(registry.pre_hooks.len(), 1); // LoggingPreHook
        assert_eq!(registry.post_hooks.len(), 0);
    }

    #[tokio::test]
    async fn test_pre_hook_success() {
        let mut registry = HookRegistry::new();
        registry.pre_hooks.push(Arc::new(MockPreHook { should_fail: false }));
        
        let ctx = HookContext {
            client_uid: Some(1000),
            method: "GET".to_string(),
            path: "/test".to_string(),
            entry_title: None,
        };

        for hook in &registry.pre_hooks {
            assert!(hook.run(&ctx).await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_pre_hook_failure() {
        let mut registry = HookRegistry::new();
        registry.pre_hooks.push(Arc::new(MockPreHook { should_fail: true }));
        
        let ctx = HookContext {
            client_uid: Some(1000),
            method: "GET".to_string(),
            path: "/test".to_string(),
            entry_title: None,
        };

        let mut results = Vec::new();
        for hook in &registry.pre_hooks {
            results.push(hook.run(&ctx).await);
        }
        assert!(results.iter().any(|r| r.is_err()));
    }

    #[tokio::test]
    async fn test_post_hook_execution() {
        let mut registry = HookRegistry::new();
        let called = Arc::new(AtomicBool::new(false));
        registry.add_post_hook(Arc::new(MockPostHook { called: called.clone() }));
        
        let ctx = HookContext {
            client_uid: Some(1000),
            method: "GET".to_string(),
            path: "/test".to_string(),
            entry_title: None,
        };

        for hook in &registry.post_hooks {
            hook.run(&ctx).await;
        }
        assert!(called.load(Ordering::SeqCst));
    }
}
