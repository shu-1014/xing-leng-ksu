//! Keep the installed secret-code receiver reachable on MIUI while its icon is hidden.
#![cfg(target_os = "android")]

use crate::{defs, webui_apps};
use anyhow::{Context, Result, bail, ensure};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const HELPER_CLASS: &str = "me.weishu.kernelsu.ui.stealth.DialerRecoveryGuard";
const LAUNCHER: &str = "me.weishu.kernelsu.Launcher";
const MAX_STATE: usize = 4096;
const START_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(clap::Subcommand, Clone, Copy, Debug)]
pub enum StealthCommand {
    /// Prepare vendor background policy before hiding the launcher icon
    Start,
    /// Stop the policy guard after restoring the launcher icon
    Stop,
    /// Show whether the policy guard is running
    Status,
}

#[derive(Debug, PartialEq, Eq)]
struct GuardState {
    pid: i32,
    started: u64,
    nonce: String,
    descriptor: i32,
    apk_device: u64,
    apk_inode: u64,
}

pub fn run(command: StealthCommand) -> Result<()> {
    match command {
        StealthCommand::Start => start(),
        StealthCommand::Stop => stop(),
        StealthCommand::Status => {
            let _lock = lock()?;
            let running = read_state()?.is_some_and(|state| process_matches(&state));
            println!(
                "{}",
                serde_json::json!({
                    "running": running,
                    "hidden": is_hidden()?,
                    "policyRequired": is_miui(),
                })
            );
            Ok(())
        }
    }
}

pub fn start() -> Result<()> {
    let _lock = lock()?;
    let result = start_locked();
    if result.is_err()
        && is_hidden().unwrap_or(false)
        && let Err(error) = restore_launcher()
    {
        log::error!("Cannot restore launcher after recovery-policy failure: {error:#}");
    }
    result
}

fn start_locked() -> Result<()> {
    stop_locked()?;
    if !is_miui() {
        return Ok(());
    }
    let (mut helper, pinned_apk) = webui_apps::manager_helper_command(HELPER_CLASS)?;
    let mut random = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let nonce = base16ct::lower::encode_string(&random);
    let descriptor = pinned_apk.as_raw_fd();
    let metadata = pinned_apk.metadata()?;
    let log = protected_file(&private_dir().join("guard.log"), false)?;
    helper
        .args([defs::DEFAULT_PACKAGE_NAME, &nonce])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(log));
    // The guard must survive the short-lived Manager/ADB command that starts it.
    unsafe {
        helper.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::umask(0o077);
            Ok(())
        });
    }
    let mut child = helper
        .spawn()
        .context("Cannot start recovery policy observer")?;
    // manager_helper_command made this descriptor inheritable in the child only.
    drop(pinned_apk);
    let state = wait_ready(&mut child, &nonce).and_then(|()| {
        let state = GuardState {
            pid: i32::try_from(child.id())?,
            started: process_start(i32::try_from(child.id())?)?,
            nonce,
            descriptor,
            apk_device: metadata.dev(),
            apk_inode: metadata.ino(),
        };
        ensure!(
            process_matches(&state),
            "Recovery observer process identity changed"
        );
        write_state(&state)?;
        Ok(state)
    });
    if let Err(error) = state {
        // Child owns this exact spawned process, so no external PID lookup is used.
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    // The helper emits a single readiness line and needs no inherited terminal.
    drop(child.stdout.take());
    // A persistent WebUI parent must reap the guard when it exits on recovery.
    // A short-lived CLI parent exits normally and Android init adopts the child.
    let _ = thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

pub fn stop() -> Result<()> {
    let _lock = lock()?;
    stop_locked()
}

fn stop_locked() -> Result<()> {
    let Some(state) = read_state()? else {
        return Ok(());
    };
    let pidfd = match open_pidfd(state.pid) {
        Ok(fd) => Some(fd),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) => None,
        Err(error) => return Err(error.into()),
    };
    // Open the pidfd before checking /proc, then signal that same process handle.
    if let Some(pidfd) = pidfd
        && process_matches(&state)
    {
        match signal_pidfd(&pidfd, libc::SIGTERM) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(error) => return Err(error.into()),
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while process_matches(&state) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        if process_matches(&state) {
            match signal_pidfd(&pidfd, libc::SIGKILL) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    remove_state()
}

// rustix excludes these APIs on Android; the pinned libc supplies both syscall
// numbers for Android arm64/x86_64 and its other supported Android architectures.
fn open_pidfd(pid: i32) -> std::io::Result<OwnedFd> {
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: Successful pidfd_open returns a new owned descriptor, with CLOEXEC.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as libc::c_int) })
}

fn signal_pidfd(pidfd: &OwnedFd, signal: libc::c_int) -> std::io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0_u32,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// End only a frozen authenticated Manager main process, allowing a cold recovery.
/// This never force-stops the package or changes another process's freezer state.
pub fn clear_frozen_manager() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Frozen Manager cleanup requires root"
    );
    let uid = webui_apps::verified_manager_appid()?;
    for (index, entry) in fs::read_dir("/proc")?.enumerate() {
        ensure!(index < 32768, "Too many process entries to inspect safely");
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        if pid <= 1 {
            continue;
        }
        let command_path = format!("/proc/{pid}/cmdline");
        if !read_bounded(&command_path, MAX_STATE).is_ok_and(|command| {
            command.split(|byte| *byte == 0).next() == Some(defs::DEFAULT_PACKAGE_NAME.as_bytes())
        }) {
            continue;
        }
        // Keep this exact process handle before any full /proc identity validation.
        let pidfd = open_pidfd(pid);
        let Some(identity) = frozen_manager_identity(pid, uid).unwrap_or(None) else {
            continue;
        };
        let pidfd = pidfd.context("Cannot safely open the frozen Manager process")?;
        ensure!(
            webui_apps::verified_manager_appid()? == uid,
            "Manager package identity changed during frozen-process cleanup"
        );
        let rechecked = match frozen_manager_identity(pid, uid) {
            Ok(value) => value,
            Err(error)
                if error.downcast_ref::<std::io::Error>().is_some_and(|cause| {
                    cause.kind() == ErrorKind::NotFound || cause.raw_os_error() == Some(libc::ESRCH)
                }) =>
            {
                continue;
            }
            Err(error) => {
                return Err(error).context("Cannot revalidate the frozen Manager process");
            }
        };
        if rechecked.as_ref() != Some(&identity) {
            continue;
        }
        match signal_pidfd(&pidfd, libc::SIGKILL) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(error) => return Err(error).context("Cannot end the frozen Manager process"),
        }
    }
    Ok(())
}

fn frozen_manager_identity(pid: i32, uid: u32) -> Result<Option<(u64, String)>> {
    let started = process_start(pid)?;
    let base = format!("/proc/{pid}");
    let status = read_bounded(&format!("{base}/status"), 64 * 1024)?;
    let status = std::str::from_utf8(&status)?;
    let Some(values) = status.lines().find_map(|line| line.strip_prefix("Uid:")) else {
        return Ok(None);
    };
    let values = values
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if values.len() != 4 || values[0] != uid || values[1] != uid {
        return Ok(None);
    }
    let command = read_bounded(&format!("{base}/cmdline"), MAX_STATE)?;
    if command.split(|byte| *byte == 0).next() != Some(defs::DEFAULT_PACKAGE_NAME.as_bytes()) {
        return Ok(None);
    }
    let cgroups = read_bounded(&format!("{base}/cgroup"), MAX_STATE)?;
    let cgroups = std::str::from_utf8(&cgroups)?;
    let Some(group) = cgroups.lines().find_map(|line| line.strip_prefix("0::")) else {
        return Ok(None);
    };
    let expected = format!("/apps/uid_{uid}/pid_{pid}");
    let Some(suffix) = group.strip_prefix(&expected) else {
        return Ok(None);
    };
    if !(suffix.is_empty() || suffix.starts_with('/'))
        || !group.split('/').skip(1).all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        })
    {
        return Ok(None);
    }
    let events = read_bounded(&format!("/sys/fs/cgroup{group}/cgroup.events"), MAX_STATE)?;
    let frozen = std::str::from_utf8(&events)?
        .lines()
        .any(|line| line.split_whitespace().collect::<Vec<_>>() == ["frozen", "1"]);
    Ok(frozen.then(|| (started, group.to_string())))
}

pub fn start_if_hidden() -> Result<()> {
    if is_hidden()? {
        start()?;
    }
    Ok(())
}

pub fn restore_launcher() -> Result<()> {
    let mut pm = Command::new("/system/bin/pm");
    pm.args([
        "enable",
        "--user",
        "0",
        &format!("{}/{LAUNCHER}", defs::DEFAULT_PACKAGE_NAME),
    ]);
    webui_apps::bounded_output(&mut pm, 4096, Duration::from_secs(5))?;
    ensure!(!is_hidden()?, "Android did not restore the launcher icon");
    Ok(())
}

fn is_miui() -> bool {
    ["ro.miui.ui.version.name", "ro.mi.os.version.name"]
        .iter()
        .any(|name| crate::utils::getprop(name).is_some_and(|value| !value.is_empty()))
}

fn is_hidden() -> Result<bool> {
    let mut dumpsys = Command::new("/system/bin/dumpsys");
    dumpsys.args(["package", defs::DEFAULT_PACKAGE_NAME]);
    let output = webui_apps::bounded_output(&mut dumpsys, 1024 * 1024, Duration::from_secs(5))?;
    let mut user_zero = false;
    let mut disabled_components = false;
    for line in std::str::from_utf8(&output)?.lines().map(str::trim) {
        if line.starts_with("User ") {
            user_zero = line.starts_with("User 0:");
            disabled_components = false;
        }
        if user_zero && line == "disabledComponents:" {
            disabled_components = true;
            continue;
        }
        if disabled_components && line == LAUNCHER {
            return Ok(true);
        }
        if disabled_components && line.contains(':') {
            disabled_components = false;
        }
    }
    Ok(false)
}

fn private_dir() -> PathBuf {
    Path::new(defs::WORKING_DIR).join("stealth")
}

fn lock() -> Result<File> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && unsafe { libc::getuid() } == 0,
        "Recovery policy requires root"
    );
    let parent = Path::new(defs::WORKING_DIR);
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    validate_directory(parent, false)?;
    let directory = private_dir();
    match DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    validate_directory(&directory, true)?;
    let lock = protected_file(&directory.join("guard.lock"), false)?;
    let deadline = Instant::now() + START_TIMEOUT + Duration::from_secs(5);
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(lock);
        }
        let error = std::io::Error::last_os_error();
        ensure!(
            error.kind() == ErrorKind::WouldBlock,
            "Cannot lock recovery policy: {error}"
        );
        ensure!(Instant::now() < deadline, "Recovery policy is busy");
        thread::sleep(Duration::from_millis(25));
    }
}

fn validate_directory(path: &Path, private: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let prohibited = if private { 0o077 } else { 0o022 };
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & prohibited == 0,
        "Recovery state directory is not protected"
    );
    Ok(())
}

fn protected_file(path: &Path, truncate: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(truncate)
        .append(!truncate)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    validate_file(&file)?;
    Ok(file)
}

fn validate_file(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode().trailing_zeros() >= 6
            && metadata.nlink() == 1,
        "Recovery state file is not protected"
    );
    Ok(())
}

fn read_state() -> Result<Option<GuardState>> {
    let path = private_dir().join("guard.pid");
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_file(&file)?;
    let mut value = String::new();
    file.take(MAX_STATE as u64 + 1).read_to_string(&mut value)?;
    ensure!(
        value.len() <= MAX_STATE,
        "Recovery process state is too large"
    );
    let fields = value.lines().collect::<Vec<_>>();
    ensure!(
        fields.len() == 7 && fields[0] == "1",
        "Invalid recovery process state"
    );
    let state = GuardState {
        pid: fields[1].parse()?,
        started: fields[2].parse()?,
        nonce: fields[3].to_string(),
        descriptor: fields[4].parse()?,
        apk_device: fields[5].parse()?,
        apk_inode: fields[6].parse()?,
    };
    ensure!(
        state.pid > 1
            && state.started > 0
            && (3..65536).contains(&state.descriptor)
            && state.nonce.len() == 64
            && state
                .nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Invalid recovery process identity"
    );
    Ok(Some(state))
}

fn write_state(state: &GuardState) -> Result<()> {
    let directory = private_dir();
    let temporary = directory.join("guard.pid.tmp");
    let mut file = protected_file(&temporary, true)?;
    write!(
        file,
        "1\n{}\n{}\n{}\n{}\n{}\n{}\n",
        state.pid, state.started, state.nonce, state.descriptor, state.apk_device, state.apk_inode
    )?;
    file.sync_all()?;
    fs::rename(&temporary, directory.join("guard.pid"))?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn remove_state() -> Result<()> {
    match fs::remove_file(private_dir().join("guard.pid")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn process_start(pid: i32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(") ")
        .context("Invalid observer process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("Missing observer process start time")?
        .parse()
        .map_err(Into::into)
}

fn process_matches(state: &GuardState) -> bool {
    (|| -> Result<bool> {
        ensure!(
            process_start(state.pid)? == state.started,
            "Observer PID was reused"
        );
        let base = format!("/proc/{}", state.pid);
        let status = fs::read_to_string(format!("{base}/status"))?;
        let uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .context("Missing observer UID")?;
        ensure!(
            uid.split_whitespace().collect::<Vec<_>>() == ["0", "0", "0", "0"],
            "Observer is not root"
        );
        let command = read_bounded(&format!("{base}/cmdline"), MAX_STATE)?;
        let fields = command.split(|byte| *byte == 0).collect::<Vec<_>>();
        let class = fields
            .iter()
            .position(|field| *field == HELPER_CLASS.as_bytes())
            .context("Observer is not the expected helper")?;
        ensure!(
            fields.get(class + 1).copied() == Some(defs::DEFAULT_PACKAGE_NAME.as_bytes())
                && fields.get(class + 2).copied() == Some(state.nonce.as_bytes()),
            "Observer arguments do not match"
        );
        let environment = read_bounded(&format!("{base}/environ"), 64 * 1024)?;
        let classpath = format!("CLASSPATH=/proc/self/fd/{}", state.descriptor);
        ensure!(
            environment
                .split(|byte| *byte == 0)
                .any(|value| value == classpath.as_bytes()),
            "Observer classpath does not match"
        );
        let apk = fs::metadata(format!("{base}/fd/{}", state.descriptor))?;
        ensure!(
            apk.is_file() && apk.dev() == state.apk_device && apk.ino() == state.apk_inode,
            "Observer pinned APK changed"
        );
        Ok(true)
    })()
    .unwrap_or(false)
}

fn read_bounded(path: &str, limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut output)?;
    ensure!(
        output.len() <= limit,
        "Observer process information exceeds its bounds"
    );
    Ok(output)
}

fn wait_ready(child: &mut Child, nonce: &str) -> Result<()> {
    let output = child
        .stdout
        .as_mut()
        .context("Missing observer readiness pipe")?;
    let fd = output.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "Cannot configure observer readiness pipe"
    );
    let expected = format!("READY {nonce}\n");
    let deadline = Instant::now() + START_TIMEOUT;
    let mut result = Vec::new();
    loop {
        let mut buffer = [0u8; 128];
        match child
            .stdout
            .as_mut()
            .context("Missing readiness pipe")?
            .read(&mut buffer)
        {
            Ok(0) => bail!("Recovery observer exited before it was ready"),
            Ok(count) => {
                result.extend_from_slice(&buffer[..count]);
                ensure!(result.len() <= 256, "Invalid observer readiness output");
                if result.ends_with(b"\n") {
                    ensure!(
                        result == expected.as_bytes(),
                        "Recovery observer did not confirm readiness"
                    );
                    ensure!(
                        child.try_wait()?.is_none(),
                        "Recovery observer exited after readiness"
                    );
                    return Ok(());
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        ensure!(
            child.try_wait()?.is_none(),
            "Recovery observer failed; see its protected log"
        );
        ensure!(
            Instant::now() < deadline,
            "Recovery observer readiness timed out"
        );
        thread::sleep(Duration::from_millis(25));
    }
}
