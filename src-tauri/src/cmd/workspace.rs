use super::{CmdResult, CommandFailure};
use crate::config::{Config, IVerge};
use std::{path::PathBuf, time::Duration};
use tokio::process::Command;

#[derive(Clone, Copy, serde::Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAction {
    Status,
    Login,
    Configure,
    Connect,
    Disconnect,
    Logout,
}

#[derive(serde::Deserialize, serde::Serialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceState {
    Unconfigured,
    SignedOut,
    SignedIn,
    Expired,
}

#[derive(serde::Deserialize, serde::Serialize, specta::Type)]
pub struct WorkspaceStatus {
    state: WorkspaceState,
    name: Option<String>,
    codex: bool,
    #[serde(default)]
    network_enabled: bool,
    #[serde(default)]
    remote_revoked: Option<bool>,
}

fn failure(code: &str) -> CommandFailure {
    CommandFailure::coded(code, "The workspace operation could not be completed")
}

async fn companion(action: &str) -> CmdResult<serde_json::Value> {
    let executable = std::env::var_os("PILGRIM_WORKSPACE_AGENT")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_file())
        .ok_or_else(|| failure("WORKSPACE_AGENT_UNAVAILABLE"))?;
    let output = tokio::time::timeout(
        Duration::from_secs(200),
        Command::new(executable).arg(action).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| failure("WORKSPACE_TIMED_OUT"))?
    .map_err(|_| failure("WORKSPACE_AGENT_UNAVAILABLE"))?;
    if !output.status.success() {
        // Never forward companion/library output containing private URLs or credentials.
        return Err(failure("WORKSPACE_OPERATION_FAILED"));
    }
    serde_json::from_slice(&output.stdout).map_err(|_| failure("WORKSPACE_INVALID_RESPONSE"))
}

async fn set_network(enabled: bool) -> CmdResult {
    super::patch_verge_config(IVerge {
        enable_system_proxy: Some(enabled),
        enable_tun_mode: if enabled { None } else { Some(false) },
        ..Default::default()
    })
    .await
}

async fn connect() -> CmdResult {
    const MARKER: &str = "pilgrim-workspace-managed-v1";
    let value = companion("network-profile").await?;
    let yaml = value
        .get("yaml")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| failure("WORKSPACE_INVALID_PROFILE"))?;
    let existing = Config::profiles()
        .await
        .data_arc()
        .items
        .as_ref()
        .and_then(|items| items.iter().find(|item| item.desc.as_deref() == Some(MARKER)))
        .and_then(|item| item.uid.clone());
    if let Some(uid) = existing {
        let outcome = super::save_profile_file(uid.to_string(), Some(yaml.to_owned())).await?;
        if !outcome.is_valid() {
            return Err(failure("WORKSPACE_INVALID_PROFILE"));
        }
    } else {
        super::create_profile(
            super::ProfileCreate {
                itype: Some("local".into()),
                name: Some("Company network".into()),
                desc: Some(MARKER.into()),
                ..Default::default()
            },
            Some(yaml.to_owned()),
        )
        .await?;
    }
    let uid = Config::profiles()
        .await
        .data_arc()
        .items
        .as_ref()
        .and_then(|items| items.iter().find(|item| item.desc.as_deref() == Some(MARKER)))
        .and_then(|item| item.uid.clone())
        .ok_or_else(|| failure("WORKSPACE_PROFILE_MISSING"))?;
    let outcome = super::patch_profiles_config(super::ProfileSelection { current: Some(uid) }).await?;
    if !outcome.is_valid() {
        return Err(failure("WORKSPACE_INVALID_PROFILE"));
    }
    set_network(true).await
}

static WORKSPACE_MUTATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tauri::command]
#[specta::specta]
pub async fn workspace_action(action: WorkspaceAction) -> CmdResult<WorkspaceStatus> {
    let _guard = if matches!(action, WorkspaceAction::Status) {
        None
    } else {
        Some(WORKSPACE_MUTATION.try_lock().map_err(|_| failure("WORKSPACE_BUSY"))?)
    };
    let result = match action {
        WorkspaceAction::Status => match companion("status").await {
            Ok(value) => value,
            Err(error) if error.code.as_deref() == Some("WORKSPACE_AGENT_UNAVAILABLE") => {
                serde_json::json!({"state": "unconfigured", "name": null, "codex": false})
            }
            Err(error) => return Err(error),
        },
        WorkspaceAction::Login => companion("login").await?,
        WorkspaceAction::Configure => companion("configure").await?,
        WorkspaceAction::Connect => {
            connect().await?;
            companion("status").await?
        }
        WorkspaceAction::Disconnect => {
            set_network(false).await?;
            companion("status").await?
        }
        WorkspaceAction::Logout => {
            let disconnect = set_network(false).await;
            let logout = companion("logout").await;
            disconnect?;
            logout?
        }
    };
    let mut status: WorkspaceStatus =
        serde_json::from_value(result).map_err(|_| failure("WORKSPACE_INVALID_RESPONSE"))?;
    let proxy = super::get_sys_proxy().await?;
    let verge = Config::verge().await.latest_arc();
    let port = Config::clash().await.latest_arc().get_mixed_port();
    let host = verge.proxy_host.as_deref().unwrap_or("127.0.0.1");
    let profiles = Config::profiles().await.data_arc();
    let company_profile = profiles.items.as_ref().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.uid == profiles.current && item.desc.as_deref() == Some("pilgrim-workspace-managed-v1"))
    });
    status.network_enabled = company_profile
        && verge.enable_system_proxy.unwrap_or(false)
        && proxy.enable
        && proxy.server == format!("{host}:{port}");
    Ok(status)
}
