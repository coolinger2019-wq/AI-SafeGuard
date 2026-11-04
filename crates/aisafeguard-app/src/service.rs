#![cfg(windows)]

//! Windows 服务化（[A.8.2/A.5.15]）：提权引擎以 LocalSystem 服务运行，
//! GUI 以普通权限进程经本地 API 连接——界面不再以管理员身份跑。
//!
//! 管理：`aisafeguard service install|uninstall|start|stop`（需要管理员）。
//! 运行：SCM 调起 `aisafeguard.exe --service`。
//! 数据目录：`%PROGRAMDATA%\aisafeguard`（服务发布 token 供 GUI 远程模式使用）。

use std::ffi::OsString;
use std::time::Duration;

use anyhow::{Result, anyhow};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

pub const SERVICE_NAME: &str = "AISafeGuard";

pub fn service_data_dir() -> Option<std::path::PathBuf> {
    crate::remote::service_data_dir()
}

// ---------- 管理子命令（需管理员） ----------

pub fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(service_err)?;
    let exe = std::env::current_exe()?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: "AI-SafeGuard Engine".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec!["--service".into()],
        dependencies: Vec::new(),
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .map_err(service_err)?;
    service
        .set_description(
            "AI-SafeGuard 提权引擎：蜜罐 / 频次检测 / 防火墙处置。GUI 以普通权限自动连接本服务。",
        )
        .map_err(service_err)?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(service_err)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::DELETE)
        .map_err(service_err)?;
    service.delete().map_err(service_err)?;
    Ok(())
}

pub fn start() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(service_err)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .map_err(service_err)?;
    service.start(&[] as &[&OsString]).map_err(service_err)?;
    Ok(())
}

pub fn stop() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(service_err)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP)
        .map_err(service_err)?;
    service.stop().map_err(service_err)?;
    Ok(())
}

/// 服务注册的二进制路径（自更新用它定位要替换的文件）。
/// QUERY_CONFIG 对普通用户通常可读，因此 GUI 未提权也能探测。
pub fn binary_path() -> Result<std::path::PathBuf> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(service_err)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG)
        .map_err(service_err)?;
    Ok(service.query_config().map_err(service_err)?.executable_path)
}

/// 轮询等待服务进入目标状态（自更新的停/起都异步，必须等到位再动文件）。
pub fn wait_state(target: ServiceState, secs: u64) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(service_err)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(service_err)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        let state = service.query_status().map_err(service_err)?.current_state;
        if state == target {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!("等待服务进入 {target:?} 超时（{secs}s）"));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn service_err(e: windows_service::Error) -> anyhow::Error {
    anyhow!("服务操作失败: {e}（需要管理员权限）")
}

// ---------- 服务工作模式 ----------

define_windows_service!(ffi_service_main, service_main);

/// `--service` 入口：交给 SCM 调度器。
pub fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| anyhow!("服务调度器启动失败: {e}"))
}

fn service_main(_args: Vec<OsString>) {
    let _ = run_service_body();
}

fn run_service_body() -> windows_service::Result<()> {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop => {
                let _ = tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
    set_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::STOP,
    )?;

    let result = {
        let status_handle = &status_handle;
        crate::run_engine_until_stop(&rx, &|| {
            let _ = set_status(
                status_handle,
                ServiceState::Running,
                ServiceControlAccept::STOP,
            );
        })
    };

    let _ = set_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
    );
    if let Err(e) = result {
        eprintln!("服务运行异常退出: {e}");
    }
    Ok(())
}

fn set_status(
    handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    accept: ServiceControlAccept,
) -> windows_service::Result<()> {
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(5),
        process_id: None,
    })
}
