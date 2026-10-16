use crate::utils::dirs;
use anyhow::{Context as _, Result};
use chrono::Local;
use std::{
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
};

const STARTUP_LOG_FILE: &str = "startup.log";

#[cfg(target_os = "macos")]
pub(crate) async fn check_network_exclusivity() -> Result<()> {
    let official = tokio::process::Command::new("/usr/bin/pgrep")
        .args(["-x", "clash-verge"])
        .output()
        .await
        .context("Could not check whether Clash Verge Rev is running")?;
    anyhow::ensure!(
        official.status.code() == Some(1),
        "Quit Clash Verge Rev before starting Pilgrim Workspace, including when its network is disconnected. Existing clients have not been stopped."
    );
    clash_verge_service_ipc::execution::check_sidecar_available()
        .await
        .context("Pilgrim Workspace cannot run alongside another mihomo core in this build. Quit Clash Verge Rev or other third-party VPN clients, then retry. Existing clients have not been stopped.")?;
    let snapshot = tokio::task::spawn_blocking(sysproxy::Sysproxy::snapshot).await??;
    anyhow::ensure!(
        snapshot.is_all_disabled(),
        "Another system proxy is enabled. Quit the third-party VPN/proxy client before starting Pilgrim Workspace. This build does not support shared system-proxy ownership; your existing proxy has been preserved."
    );
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn report_network_conflict(error: &anyhow::Error) {
    let detail = format!("{error:#}");
    eprintln!("[pilgrim-workspace] startup warning: {detail}");
    if let Err(log_error) = startup_log_path().and_then(|path| append_event(&path, "WARN", &detail)) {
        eprintln!("[pilgrim-workspace] failed to write startup log: {log_error:#}");
    }
    let _ = rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Warning)
        .set_title("Pilgrim Workspace")
        .set_description("请先退出其他 VPN 或代理\n\n当前版本暂不支持与 Clash Verge Rev 或其他 VPN / 代理客户端同时运行。请退出它们后，再启动 Pilgrim Workspace。\n\n你的现有网络连接未被更改。")
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}

pub(crate) fn report_error(error: &anyhow::Error) {
    let detail = format!("{error:#}");
    eprintln!("[pilgrim-workspace] startup failed: {detail}");

    let log_result = startup_log_path().and_then(|path| {
        append_event(&path, "ERROR", &detail).with_context(|| format!("startup log {}", path.display()))?;
        Ok(path)
    });
    let message = match log_result {
        Ok(path) => format!(
            "暂时无法启动\n\n请稍后重试。如果仍然无法启动，请联系公司支持并提供诊断日志：\n{}",
            path.display()
        ),
        Err(log_error) => {
            eprintln!("[pilgrim-workspace] failed to write startup log: {log_error:#}");
            "暂时无法启动\n\n请稍后重试。如果仍然无法启动，请联系公司支持。本次诊断日志未能保存。".into()
        }
    };
    let _ = rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Warning)
        .set_title("Pilgrim Workspace")
        .set_description(message)
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}

fn startup_log_path() -> Result<PathBuf> {
    Ok(dirs::preinit_app_data_dir()?.join("logs").join(STARTUP_LOG_FILE))
}

fn append_event(path: &Path, level: &str, detail: &str) -> Result<()> {
    let parent = path.parent().context("startup log has no parent directory")?;
    std::fs::create_dir_all(parent).context("failed to create startup log directory")?;

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).context("failed to open startup log")?;
    writeln!(
        file,
        "[{}] {level} [Startup] {detail}",
        Local::now().format("%Y-%m-%d %H:%M:%S%.3f")
    )
    .context("failed to write startup log")?;
    file.flush().context("failed to flush startup log")?;
    Ok(())
}
