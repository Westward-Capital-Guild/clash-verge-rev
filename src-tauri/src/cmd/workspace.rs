use super::{CmdResult, CommandFailure};
use crate::config::{Config, IVerge};
use std::{path::PathBuf, time::Duration};
use tokio::process::Command;

#[derive(Clone, Copy, serde::Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAction {
    Status,
    Login,
    LoginFeishu,
    LoginAuthentik,
    Configure,
    Connect,
    Update,
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
#[serde(rename_all = "snake_case")]
pub enum WorkspaceProvider {
    Feishu,
    Authentik,
}

#[derive(serde::Deserialize, serde::Serialize, specta::Type)]
pub struct WorkspaceStatus {
    state: WorkspaceState,
    name: Option<String>,
    codex: bool,
    #[serde(default)]
    providers: Vec<WorkspaceProvider>,
    #[serde(default)]
    provider: Option<WorkspaceProvider>,
    #[serde(default)]
    network_enabled: bool,
    #[serde(default)]
    remote_revoked: Option<bool>,
    #[serde(default)]
    company: bool,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    capabilities: Option<WorkspaceCapabilities>,
    #[serde(default)]
    network_stage: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize, specta::Type)]
pub struct WorkspaceCapabilities {
    network: String,
    development_hosts: String,
    local_model: String,
}

fn failure(code: &str) -> CommandFailure {
    CommandFailure::coded(code, "The workspace operation could not be completed")
}

async fn companion(action: &str) -> CmdResult<serde_json::Value> {
    companion_args(&[action]).await
}

static COMPANION_CANCEL: tokio::sync::Notify = tokio::sync::Notify::const_new();
static REMOTE_CANCEL: tokio::sync::Notify = tokio::sync::Notify::const_new();

#[cfg(unix)]
struct CompanionGroup(u32);

#[cfg(unix)]
impl Drop for CompanionGroup {
    fn drop(&mut self) {
        if self.0 != 0 {
            // The companion gets its own process group; never target other SSH clients.
            unsafe { libc::kill(-(self.0 as i32), libc::SIGKILL) };
        }
    }
}

async fn companion_args(args: &[&str]) -> CmdResult<serde_json::Value> {
    let bundled = crate::utils::dirs::app_resources_dir()
        .ok()
        .map(|dir| dir.join("companion/pilgrim-workspace-agent"));
    #[cfg(target_os = "windows")]
    let bundled = bundled.map(|path| path.with_extension("exe"));
    let executable = std::env::var_os("PILGRIM_WORKSPACE_AGENT")
        .map(PathBuf::from)
        .or(bundled)
        .filter(|path| path.is_absolute() && path.is_file())
        .ok_or_else(|| failure("WORKSPACE_AGENT_UNAVAILABLE"))?;
    let mut command = Command::new(executable);
    command
        .args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(url) = option_env!("PILGRIM_WORKSPACE_BOOTSTRAP_URL") {
        command.env("PILGRIM_WORKSPACE_BOOTSTRAP_URL", url);
        command.env_remove("PILGRIM_WORKSPACE_CONFIG");
    }
    #[cfg(unix)]
    command.process_group(0);
    let remote = args.first().is_some_and(|name| name.starts_with("remote-"));
    if remote {
        let proxy = super::get_sys_proxy().await?;
        let port = Config::clash().await.latest_arc().get_mixed_port();
        if proxy.enable && proxy.server == format!("127.0.0.1:{port}") {
            command.env("PILGRIM_WORKSPACE_SOCKS_PORT", port.to_string());
        } else {
            command.env_remove("PILGRIM_WORKSPACE_SOCKS_PORT");
        }
    }
    let child = command.spawn().map_err(|_| failure("WORKSPACE_AGENT_UNAVAILABLE"))?;
    #[cfg(unix)]
    let mut group = CompanionGroup(child.id().unwrap_or(0));
    let output = tokio::select! {
        biased;
        () = COMPANION_CANCEL.notified() => return Err(failure("WORKSPACE_CANCELLED")),
        () = REMOTE_CANCEL.notified(), if remote => return Err(failure("WORKSPACE_CANCELLED")),
        result = tokio::time::timeout(Duration::from_secs(200), child.wait_with_output()) => {
            result.map_err(|_| failure("WORKSPACE_TIMED_OUT"))?
                .map_err(|_| failure("WORKSPACE_AGENT_UNAVAILABLE"))?
        }
    };
    #[cfg(unix)]
    {
        group.0 = 0;
    }
    if !output.status.success() {
        // Never forward companion/library output containing private URLs or credentials.
        const CODES: &[&str] = &[
            "INVALID_SESSION",
            "MEMBER_NOT_REGISTERED",
            "MEMBER_BINDING_MISMATCH",
            "NETWORK_NOT_GRANTED",
            "LOCAL_KEY_REQUIRED",
            "RESOURCE_NOT_FOUND",
            "BINDING_CHANGED",
            "INVALID_REQUEST",
            "UNSUPPORTED_VERSION",
            "RESOURCE_NOT_READY",
            "WORKSPACE_UNAVAILABLE",
            "PROFILE_TOO_LARGE",
            "INVALID_PROFILE",
            "INVALID_BOOTSTRAP",
            "INVALID_POLICY",
            "INVALID_RESPONSE",
            "HTTPS_REQUIRED",
            "INVALID_ENDPOINT",
            "ENDPOINT_ORIGIN_MISMATCH",
            "REDIRECT_FORBIDDEN",
            "SESSION_EXPIRED",
            "SIGN_IN_REQUIRED",
            "SIGN_OUT_FIRST",
            "SIGN_IN_CANCELLED",
            "SIGN_IN_TIMED_OUT",
            "OS_KEYRING_UNAVAILABLE",
            "LOCAL_MODEL_NOT_GRANTED",
        ];
        let code = output
            .stderr
            .split(|byte| *byte == b'\n')
            .rev()
            .find_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            });
        return Err(failure(
            code.as_deref()
                .filter(|code| CODES.contains(code))
                .unwrap_or("WORKSPACE_OPERATION_FAILED"),
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|_| failure("WORKSPACE_INVALID_RESPONSE"))
}

static NETWORK_STAGE: parking_lot::Mutex<&str> = parking_lot::Mutex::new("disconnected");

async fn set_network(enabled: bool) -> CmdResult {
    super::patch_verge_config(IVerge {
        enable_system_proxy: Some(enabled),
        proxy_auto_config: if enabled { Some(false) } else { None },

        ..Default::default()
    })
    .await
    .map_err(|error| {
        if error.detail.contains("SYSPROXY_RESTORE_FAILED") {
            failure("SYSPROXY_RESTORE_FAILED")
        } else if error.detail.contains("SYSPROXY_SNAPSHOT_FAILED") {
            failure("SYSPROXY_SNAPSHOT_FAILED")
        } else {
            error
        }
    })?;
    if !enabled {
        *NETWORK_STAGE.lock() = "disconnected";
    }
    Ok(())
}

struct TemporaryProfile(PathBuf);
impl Drop for TemporaryProfile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn connect() -> CmdResult {
    *NETWORK_STAGE.lock() = "downloading";
    let result = connect_inner().await;
    if result.is_err() {
        let mut stage = NETWORK_STAGE.lock();
        *stage = match *stage {
            "downloading" => "download_failed",
            "downloaded" => "validation_failed",
            "validated" => "import_failed",
            "imported" => "activation_failed",
            _ => "proxy_enable_failed",
        };
    }
    result
}

async fn connect_inner() -> CmdResult {
    use sha2::{Digest as _, Sha256};
    use std::io::Write as _;
    const MARKER: &str = "pilgrim-workspace-managed-v2:";
    let value = companion("network-profile").await?;
    let yaml = value
        .get("yaml")
        .and_then(serde_json::Value::as_str)
        .filter(|yaml| yaml.len() <= 2_000_000)
        .ok_or_else(|| failure("WORKSPACE_INVALID_PROFILE"))?;
    *NETWORK_STAGE.lock() = "downloaded";
    let shape: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(yaml).map_err(|_| failure("WORKSPACE_INVALID_PROFILE"))?;
    if !shape.is_mapping()
        || shape
            .get("tun")
            .and_then(|tun| tun.get("enable"))
            .and_then(serde_yaml_ng::Value::as_bool)
            == Some(true)
    {
        return Err(failure("WORKSPACE_INVALID_PROFILE"));
    }
    // Validate privately before publishing anything through upstream profile operations.
    let path = crate::utils::dirs::app_home_dir()
        .map_err(|_| failure("WORKSPACE_IMPORT_FAILED"))?
        .join(format!(".workspace-{}.yaml", nanoid::nanoid!()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|_| failure("WORKSPACE_IMPORT_FAILED"))?;
    let _temporary = TemporaryProfile(path.clone());
    file.write_all(yaml.as_bytes())
        .map_err(|_| failure("WORKSPACE_IMPORT_FAILED"))?;
    drop(file);
    let core = Config::verge().await.latest_arc().get_valid_clash_core();
    let binary = std::env::current_exe()
        .map_err(|_| failure("WORKSPACE_VALIDATION_FAILED"))?
        .with_file_name(core.as_str());
    #[cfg(target_os = "windows")]
    let binary = binary.with_extension("exe");
    let mut validation = Command::new(binary);
    validation
        .args([
            "-t",
            "-d",
            path.parent()
                .and_then(|dir| dir.to_str())
                .ok_or_else(|| failure("WORKSPACE_VALIDATION_FAILED"))?,
            "-f",
            path.to_str().ok_or_else(|| failure("WORKSPACE_VALIDATION_FAILED"))?,
        ])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    validation.process_group(0);
    let child = validation.spawn().map_err(|_| failure("WORKSPACE_VALIDATION_FAILED"))?;
    #[cfg(unix)]
    let mut group = CompanionGroup(child.id().unwrap_or(0));
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .map_err(|_| failure("WORKSPACE_VALIDATION_FAILED"))?
        .map_err(|_| failure("WORKSPACE_VALIDATION_FAILED"))?;
    #[cfg(unix)]
    {
        group.0 = 0;
    }
    let validation = if output.status.success() {
        Ok(())
    } else {
        Err(failure("WORKSPACE_INVALID_PROFILE"))
    };
    validation?;
    *NETWORK_STAGE.lock() = "validated";
    let marker = format!(
        "{MARKER}{}",
        Sha256::digest(yaml.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let previous = Config::profiles().await.data_arc().current.clone();
    let find_uid = || async {
        Config::profiles()
            .await
            .data_arc()
            .items
            .as_ref()
            .and_then(|items| items.iter().find(|item| item.desc.as_deref() == Some(marker.as_str())))
            .and_then(|item| item.uid.clone())
    };
    if find_uid().await.is_none() {
        super::create_profile(
            super::ProfileCreate {
                itype: Some("local".into()),
                name: Some("Company network".into()),
                desc: Some(marker.clone().into()),
                ..Default::default()
            },
            Some(yaml.to_owned()),
        )
        .await
        .map_err(|_| failure("WORKSPACE_IMPORT_FAILED"))?;
    }
    let uid = find_uid().await.ok_or_else(|| failure("WORKSPACE_IMPORT_FAILED"))?;
    *NETWORK_STAGE.lock() = "imported";
    let outcome = super::patch_profiles_config(super::ProfileSelection { current: Some(uid) })
        .await
        .map_err(|_| failure("WORKSPACE_ACTIVATION_FAILED"))?;
    if !outcome.is_valid() {
        return Err(failure("WORKSPACE_ACTIVATION_FAILED"));
    }
    *NETWORK_STAGE.lock() = "profile_selected";
    if let Err(error) = set_network(true).await {
        // A failed update keeps the previously working selection available.
        if previous.is_some() {
            let _ = super::patch_profiles_config(super::ProfileSelection { current: previous }).await;
        }
        return Err(error);
    }
    *NETWORK_STAGE.lock() = "system_proxy_enabled_reachability_unverified";
    Ok(())
}

static WORKSPACE_MUTATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static REMOTE_MUTATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tauri::command]
#[specta::specta]
pub async fn workspace_action(action: WorkspaceAction) -> CmdResult<WorkspaceStatus> {
    if crate::core::handle::Handle::global().is_exiting() {
        return Err(failure("WORKSPACE_CANCELLED"));
    }
    let _remote_guard = if matches!(action, WorkspaceAction::Logout) {
        REMOTE_CANCEL.notify_waiters();
        Some(REMOTE_MUTATION.lock().await)
    } else {
        None
    };
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
        WorkspaceAction::LoginFeishu => companion("login-feishu").await?,
        WorkspaceAction::LoginAuthentik => companion("login-authentik").await?,
        WorkspaceAction::Configure => companion("configure").await?,
        WorkspaceAction::Connect | WorkspaceAction::Update => {
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
        items.iter().any(|item| {
            item.uid == profiles.current
                && item.desc.as_deref().is_some_and(|desc| {
                    desc == "pilgrim-workspace-managed-v1" || desc.starts_with("pilgrim-workspace-managed-v2:")
                })
        })
    });
    status.network_enabled = company_profile
        && verge.enable_system_proxy.unwrap_or(false)
        && proxy.enable
        && proxy.server == format!("{host}:{port}");
    let stage = *NETWORK_STAGE.lock();
    status.network_stage = Some(
        if status.network_enabled && stage == "disconnected" {
            "system_proxy_enabled_reachability_unverified"
        } else {
            stage
        }
        .into(),
    );
    Ok(status)
}

#[derive(Clone, Copy, serde::Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRemoteAction {
    Hosts,
    Prepare,
    Check,
}

#[derive(serde::Deserialize, serde::Serialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRemoteState {
    Unconfigured,
    SignedOut,
    Available,
    Unassigned,
    Unavailable,
    NotAuthorized,
    MissingKey,
    UnverifiedHost,
    InvalidHost,
    ConfigConflict,
    SshPrepared,
    SshReady,
    Unreachable,
    CodexUnavailable,
    BindingChanged,
    KeyMismatch,
    HostKeyConflict,
    PermissionDenied,
    DesktopConfigConflict,
    NetworkRequired,
}

#[derive(serde::Deserialize, serde::Serialize, specta::Type)]
pub struct WorkspaceRemoteDirectory {
    id: String,
    display_name: String,
    #[serde(default)]
    path: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize, specta::Type)]
pub struct WorkspaceRemoteHost {
    id: String,
    display_name: String,
    #[serde(default)]
    network_requirement: Option<String>,
    workspaces: Vec<WorkspaceRemoteDirectory>,
}

#[derive(serde::Deserialize, serde::Serialize, specta::Type)]
pub struct WorkspaceRemoteStatus {
    #[serde(default)]
    code: Option<String>,
    state: WorkspaceRemoteState,
    hosts: Vec<WorkspaceRemoteHost>,
    alias: Option<String>,
    path: Option<String>,
}

#[tauri::command]
#[specta::specta]
pub async fn workspace_remote(
    action: WorkspaceRemoteAction,
    host_id: Option<String>,
    workspace_id: Option<String>,
) -> CmdResult<WorkspaceRemoteStatus> {
    if crate::core::handle::Handle::global().is_exiting() {
        return Err(failure("WORKSPACE_CANCELLED"));
    }
    let _guard = REMOTE_MUTATION.try_lock().map_err(|_| failure("WORKSPACE_BUSY"))?;
    let name = match action {
        WorkspaceRemoteAction::Hosts => "remote-hosts",
        WorkspaceRemoteAction::Prepare => "remote-prepare",
        WorkspaceRemoteAction::Check => "remote-check",
    };
    let mut args = vec![name];
    if !matches!(action, WorkspaceRemoteAction::Hosts) {
        args.extend([
            "--host-id",
            host_id.as_deref().ok_or_else(|| failure("WORKSPACE_HOST_REQUIRED"))?,
            "--workspace-id",
            workspace_id
                .as_deref()
                .ok_or_else(|| failure("WORKSPACE_HOST_REQUIRED"))?,
        ]);
    }
    let value = match companion_args(&args).await {
        Ok(value) => value,
        Err(error) if error.code.as_deref() == Some("WORKSPACE_AGENT_UNAVAILABLE") => {
            serde_json::json!({"state": "unconfigured", "hosts": []})
        }
        Err(error) => return Err(error),
    };
    serde_json::from_value(value).map_err(|_| failure("WORKSPACE_INVALID_RESPONSE"))
}

pub(crate) async fn cancel_workspace_companions() {
    COMPANION_CANCEL.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _guards = tokio::join!(WORKSPACE_MUTATION.lock(), REMOTE_MUTATION.lock());
    })
    .await;
}

#[cfg(all(test, unix))]
mod tests {
    use super::CompanionGroup;
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
    use tokio::process::Command;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn workspace_remote_cancellation_stops_its_child_process_group() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30 & echo ready; wait"])
            .process_group(0)
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let group = CompanionGroup(child.id().unwrap());
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        timeout(Duration::from_secs(3), output.read_line(&mut ready))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ready.trim(), "ready");
        drop(group);
        timeout(Duration::from_secs(3), child.wait()).await.unwrap().unwrap();
        // A surviving descendant would keep the inherited stdout pipe open.
        timeout(Duration::from_secs(3), output.read_to_end(&mut Vec::new()))
            .await
            .unwrap()
            .unwrap();
    }
}
