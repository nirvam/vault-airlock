use crate::hooks::{HookContext, HookRegistry};
use crate::vault::{Vault, VaultEntry, VaultNode};
use anyhow::Context;
use axum::{
    extract::{connect_info::Connected, ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    serve::IncomingStream,
    Json,
};
use secrecy::SecretString;
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct UdsConnectInfo {
    pub uid: u32,
}

impl Connected<IncomingStream<'_, UnixListener>> for UdsConnectInfo {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        let cred = stream.io().peer_cred().unwrap();
        Self {
            uid: cred.uid(),
        }
    }
}

pub struct AppState {
    pub vault: RwLock<Option<Vault>>,
    pub hooks: HookRegistry,
    pub kdbx_path: std::path::PathBuf,
}

#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
}

#[derive(Deserialize)]
pub struct UnlockRequest {
    pub password: SecretString,
}

// --- Auth Handlers ---

pub async fn unlock(
    State(state): State<Arc<AppState>>,
    ConnectInfo(conn): ConnectInfo<UdsConnectInfo>,
    Json(req): Json<UnlockRequest>,
) -> Result<impl IntoResponse, AppError> {
    // 1. 审计：记录解锁尝试 (不含密码)
    let ctx = HookContext {
        client_uid: Some(conn.uid),
        method: "POST".to_string(),
        path: "/vault/unlock".to_string(),
        entry_title: None,
    };
    state.hooks.run_pre(&ctx).await.map_err(AppError::HookRejected)?;

    let mut guard = state.vault.write().await;
    if guard.is_some() {
        return Err(AppError::HookRejected("Vault is already unlocked".to_string()));
    }

    // 2. 执行解锁。req 在此块结束后自动 Drop 并 Zeroize 内存
    let vault = Vault::load(&state.kdbx_path, req.password)
        .context("Failed to decrypt KDBX database")?;
    
    *guard = Some(vault);

    // 3. 审计：记录解锁成功
    state.hooks.run_post(&ctx).await;
    
    Ok(StatusCode::OK)
}

pub async fn lock(
    State(state): State<Arc<AppState>>,
    ConnectInfo(conn): ConnectInfo<UdsConnectInfo>,
) -> impl IntoResponse {
    let ctx = HookContext {
        client_uid: Some(conn.uid),
        method: "POST".to_string(),
        path: "/vault/lock".to_string(),
        entry_title: None,
    };
    
    let mut guard = state.vault.write().await;
    *guard = None; // 丢弃旧 Vault 实例，触发其内部数据的内存清理

    state.hooks.run_post(&ctx).await;
    StatusCode::OK
}

// --- Data Handlers ---

pub async fn get_tree(
    State(state): State<Arc<AppState>>,
    ConnectInfo(conn): ConnectInfo<UdsConnectInfo>,
) -> Result<Json<VaultNode>, AppError> {
    let vault_guard = state.vault.read().await;
    let vault = vault_guard.as_ref().ok_or(AppError::Locked)?;

    let ctx = HookContext {
        client_uid: Some(conn.uid),
        method: "GET".to_string(),
        path: "/vault/tree".to_string(),
        entry_title: None,
    };

    state.hooks.run_pre(&ctx).await.map_err(AppError::HookRejected)?;
    let tree = vault.get_tree();
    state.hooks.run_post(&ctx).await;

    Ok(Json(tree))
}

pub async fn get_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(conn): ConnectInfo<UdsConnectInfo>,
    Path(uuid): Path<String>,
) -> Result<Json<VaultEntry>, AppError> {
    let vault_guard = state.vault.read().await;
    let vault = vault_guard.as_ref().ok_or(AppError::Locked)?;

    let entry = vault.find_entry(&uuid).ok_or(AppError::NotFound)?;

    let ctx = HookContext {
        client_uid: Some(conn.uid),
        method: "GET".to_string(),
        path: format!("/vault/entry/{}", uuid),
        entry_title: Some(entry.title.clone()),
    };

    state.hooks.run_pre(&ctx).await.map_err(AppError::HookRejected)?;
    state.hooks.run_post(&ctx).await;

    Ok(Json(entry))
}

pub async fn search(
    State(state): State<Arc<AppState>>,
    ConnectInfo(conn): ConnectInfo<UdsConnectInfo>,
    Json(req): Json<SearchRequest>,
) -> Result<Json<Vec<VaultEntry>>, AppError> {
    let vault_guard = state.vault.read().await;
    let vault = vault_guard.as_ref().ok_or(AppError::Locked)?;

    let ctx = HookContext {
        client_uid: Some(conn.uid),
        method: "POST".to_string(),
        path: "/vault/search".to_string(),
        entry_title: None,
    };

    state.hooks.run_pre(&ctx).await.map_err(AppError::HookRejected)?;
    let results = vault.search(&req.query);
    state.hooks.run_post(&ctx).await;

    Ok(Json(results))
}

pub async fn health() -> impl IntoResponse {
    StatusCode::OK
}

// --- Internal ---

pub enum AppError {
    Locked,
    NotFound,
    HookRejected(String),
    Internal(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Locked => (StatusCode::LOCKED, "Database is locked").into_response(),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not Found").into_response(),
            AppError::HookRejected(msg) => (StatusCode::FORBIDDEN, msg).into_response(),
            AppError::Internal(e) => {
                tracing::error!("Internal server error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {}", e)).into_response()
            }
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn setup_state() -> Arc<AppState> {
        Arc::new(AppState {
            vault: RwLock::new(None),
            hooks: HookRegistry::new(),
            kdbx_path: PathBuf::from("test.kdbx"),
        })
    }

    fn mock_conn() -> ConnectInfo<UdsConnectInfo> {
        ConnectInfo(UdsConnectInfo { uid: 1000 })
    }

    #[tokio::test]
    async fn test_health_handler() {
        let res = health().await.into_response();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_unlock_handler_success() {
        let state = setup_state();
        let conn = mock_conn();
        let req = UnlockRequest {
            password: SecretString::new("dQ;2<?dA4\\TfgF\\:".to_string().into()),
        };

        let res = unlock(State(state.clone()), conn, Json(req)).await;
        assert!(res.is_ok());
        
        let guard = state.vault.read().await;
        assert!(guard.is_some());
    }

    #[tokio::test]
    async fn test_unlock_handler_failure() {
        let state = setup_state();
        let conn = mock_conn();
        let req = UnlockRequest {
            password: SecretString::new("wrong".to_string().into()),
        };

        let res = unlock(State(state), conn, Json(req)).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_lock_handler() {
        let state = setup_state();
        let conn = mock_conn();
        
        // Manual unlock first
        {
            let vault = Vault::load("test.kdbx", SecretString::new("dQ;2<?dA4\\TfgF\\:".to_string().into())).unwrap();
            let mut guard = state.vault.write().await;
            *guard = Some(vault);
        }

        let res = lock(State(state.clone()), conn).await.into_response();
        assert_eq!(res.status(), StatusCode::OK);
        
        let guard = state.vault.read().await;
        assert!(guard.is_none());
    }

    #[tokio::test]
    async fn test_get_tree_locked() {
        let state = setup_state();
        let conn = mock_conn();
        
        let res = get_tree(State(state), conn).await;
        match res {
            Err(AppError::Locked) => (),
            _ => panic!("Expected Locked error"),
        }
    }
}
