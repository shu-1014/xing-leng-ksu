//! Read localized installed-app labels through Android PackageManager, for display only.
use crate::defs;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_OUTPUT: usize = 4 * 1024 * 1024;
const MAX_APPS: usize = 10000;
const LABEL_HELPER: &str = "me.weishu.kernelsu.webui.WebAppLabels";
const LOCALE_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const FAILURE_BACKOFF: Duration = Duration::from_secs(30);
const CACHE_MAX_AGE: Duration = Duration::from_secs(600);

#[derive(Clone, Debug)]
pub struct AppMetadata {
    pub uid: u32,
    pub label: String,
    pub system: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PackageStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CacheKey {
    packages: Option<PackageStamp>,
    locale: String,
}

#[derive(Default)]
struct LabelCache {
    key: Option<CacheKey>,
    apps: HashMap<String, AppMetadata>,
    locale: String,
    locale_checked: Option<Instant>,
    attempted: Option<Instant>,
    updated: Option<Instant>,
    succeeded: bool,
}

/// Missing metadata must fall back to the package name; it never decides authorization.
/// Callers should only attach a label when its UID matches the packages.list entry.
pub fn labels() -> HashMap<String, AppMetadata> {
    static CACHE: OnceLock<Mutex<LabelCache>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(LabelCache::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    if cache
        .locale_checked
        .is_none_or(|checked| now.duration_since(checked) >= LOCALE_CHECK_INTERVAL)
    {
        if let Some(locale) = current_locale() {
            cache.locale = locale;
        }
        cache.locale_checked = Some(now);
    }
    let key = CacheKey {
        packages: package_stamp(),
        locale: cache.locale.clone(),
    };
    let fresh = cache.key.as_ref() == Some(&key)
        && cache
            .updated
            .is_some_and(|updated| now.duration_since(updated) < CACHE_MAX_AGE);
    let backing_off = !cache.succeeded
        && cache
            .attempted
            .is_some_and(|attempted| now.duration_since(attempted) < FAILURE_BACKOFF);
    if !fresh && !backing_off {
        cache.attempted = Some(now);
        cache.succeeded = false;
        match load_labels(&key.locale) {
            Ok(apps) => {
                cache.apps = apps;
                cache.key = Some(key);
                cache.updated = Some(Instant::now());
                cache.succeeded = true;
            }
            Err(error) => {
                log::debug!("Android app labels unavailable: {error:#}");
            }
        }
    }
    cache.apps.clone()
}

fn package_stamp() -> Option<PackageStamp> {
    let metadata = fs::metadata("/data/system/packages.list").ok()?;
    Some(PackageStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

fn current_locale() -> Option<String> {
    let mut settings = Command::new("/system/bin/cmd");
    settings.args(["settings", "--user", "0", "get", "system", "system_locales"]);
    if let Ok(output) = bounded_output(&mut settings, 4096, Duration::from_secs(2))
        && let Ok(output) = std::str::from_utf8(&output)
        && valid_locale(output.trim())
    {
        return Some(output.trim().to_string());
    }
    // Some OEMs leave persist.sys.locale empty; ActivityManager still knows the locale.
    let mut activity = Command::new("/system/bin/cmd");
    activity.args(["activity", "get-config"]);
    if let Ok(output) = bounded_output(&mut activity, 16 * 1024, Duration::from_secs(2))
        && let Ok(output) = std::str::from_utf8(&output)
        && let Some(locale) = configuration_locale(output)
    {
        return Some(locale);
    }
    crate::utils::getprop("persist.sys.locale")
        .filter(|value| valid_locale(value))
        .or_else(|| crate::utils::getprop("ro.product.locale").filter(|value| valid_locale(value)))
}

fn valid_locale(value: &str) -> bool {
    !value.is_empty()
        && value != "null"
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b',')
}

fn configuration_locale(output: &str) -> Option<String> {
    let configuration = output
        .lines()
        .find_map(|line| line.trim().strip_prefix("config: "))?;
    let prefix = configuration
        .split("-ldltr")
        .next()?
        .split("-ldrtl")
        .next()?;
    let locale = prefix
        .split('-')
        .filter(|part| !part.starts_with("mcc") && !part.starts_with("mnc"))
        .collect::<Vec<_>>()
        .join("-")
        .replace("-r", "-")
        .split(',')
        .map(|locale| {
            locale
                .strip_prefix("b+")
                .unwrap_or(locale)
                .replace('+', "-")
        })
        .collect::<Vec<_>>()
        .join(",");
    valid_locale(&locale).then_some(locale)
}

fn load_labels(locale: &str) -> Result<HashMap<String, AppMetadata>> {
    let (mut helper, pinned_apk) = manager_helper_command(LABEL_HELPER)?;
    if valid_locale(locale) {
        helper.arg(locale);
    }
    let output = bounded_output(&mut helper, MAX_OUTPUT, Duration::from_secs(15))?;
    drop(pinned_apk);
    parse_labels(&output)
}

/// Keep the returned APK open until spawn; the child inherits the verified inode.
pub fn manager_helper_command(class: &'static str) -> Result<(Command, File)> {
    // A package-name match alone must never allow an APK to execute as root.
    let manager_uid = verified_manager_appid()?;
    let packages_before = package_stamp().context("Missing package identity stamp")?;
    let mut pm = Command::new("/system/bin/pm");
    pm.args(["path", "--user", "0", defs::DEFAULT_PACKAGE_NAME]);
    let output = bounded_output(&mut pm, 64 * 1024, Duration::from_secs(3))?;
    let apk = manager_apk(std::str::from_utf8(&output)?)?;
    let apk = apk.canonicalize()?;
    let package_directory = apk
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .context("Invalid Manager APK package directory")?;
    ensure!(
        apk.starts_with("/data/app")
            && package_directory.starts_with(&format!("{}-", defs::DEFAULT_PACKAGE_NAME)),
        "Manager APK path does not match the verified package"
    );
    let pinned_apk = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&apk)?;
    let metadata = pinned_apk.metadata()?;
    ensure!(
        metadata.is_file()
            && matches!(metadata.uid(), 0 | 1000)
            && metadata.mode() & 0o022 == 0
            && metadata.len() > 0
            && metadata.len() <= 256 * 1024 * 1024,
        "Manager APK is not a protected package file"
    );
    ensure!(
        verified_manager_appid()? == manager_uid
            && package_stamp().as_ref() == Some(&packages_before),
        "Manager identity changed while reading its APK"
    );
    let descriptor = pinned_apk.as_raw_fd();
    let descriptor_path = format!("/proc/self/fd/{descriptor}");
    let (certificate_size, certificate_hash) =
        crate::apk_sign::get_apk_signature(&descriptor_path)?;
    ensure!(
        certificate_size == defs::MANAGER_CERT_SIZE.parse::<u32>()?
            && certificate_hash == defs::MANAGER_CERT_HASH,
        "Manager APK signing certificate does not match this kernel build"
    );
    let mut helper = Command::new("/system/bin/app_process");
    helper
        .env("CLASSPATH", descriptor_path)
        .args(["/system/bin", class]);
    // Preserve this already-open inode if Android atomically replaces the APK.
    unsafe {
        helper.pre_exec(move || {
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags < 0 || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok((helper, pinned_apk))
}

pub fn verified_manager_appid() -> Result<u32> {
    let appid = crate::ksucalls::manager_appid()?;
    ensure!(
        (10_000..100_000).contains(&appid),
        "No kernel-authenticated Android Manager is available"
    );
    let file = File::open("/data/system/packages.list")?;
    ensure!(
        file.metadata()?.len() <= MAX_OUTPUT as u64,
        "Package identity list is too large"
    );
    let mut packages = String::new();
    file.take(MAX_OUTPUT as u64 + 1)
        .read_to_string(&mut packages)?;
    ensure!(
        packages.len() <= MAX_OUTPUT,
        "Package identity list exceeds limit"
    );
    let mut matching = packages.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != defs::DEFAULT_PACKAGE_NAME {
            return None;
        }
        Some(fields)
    });
    let mut fields = matching
        .next()
        .context("Manager package is not installed")?;
    ensure!(
        matching.next().is_none(),
        "Duplicate Manager package identity"
    );
    let uid = fields
        .next()
        .context("Missing Manager package UID")?
        .parse::<u32>()?;
    let _debuggable = fields.next().context("Missing Manager package flags")?;
    let data_directory = fields
        .next()
        .context("Missing Manager package data directory")?;
    ensure!(
        uid == appid
            && (data_directory == format!("/data/user/0/{}", defs::DEFAULT_PACKAGE_NAME)
                || data_directory == format!("/data/data/{}", defs::DEFAULT_PACKAGE_NAME)),
        "Manager package does not match the kernel-authenticated identity"
    );
    Ok(appid)
}

fn manager_apk(output: &str) -> Result<PathBuf> {
    let mut candidates = Vec::new();
    for line in output.lines() {
        let Some(value) = line.trim().strip_prefix("package:") else {
            continue;
        };
        let path = Path::new(value);
        ensure!(
            value.len() <= 4096
                && !value.contains([':', '\0'])
                && !value.chars().any(char::is_control)
                && path.is_absolute()
                && path.extension().is_some_and(|extension| extension == "apk")
                && path.is_file(),
            "Invalid Manager APK path"
        );
        candidates.push(path.to_path_buf());
    }
    candidates
        .iter()
        .find(|path| path.file_name().is_some_and(|name| name == "base.apk"))
        .or_else(|| candidates.first())
        .cloned()
        .context("Installed Manager APK is unavailable")
}

fn parse_labels(output: &[u8]) -> Result<HashMap<String, AppMetadata>> {
    ensure!(
        output.len() <= MAX_OUTPUT,
        "App metadata exceeds size limit"
    );
    let result: Value = serde_json::from_slice(output)?;
    ensure!(
        result["schema"] == 1 && result["user"] == 0,
        "Unsupported app metadata schema or Android user"
    );
    let apps = result["apps"].as_array().context("Missing app metadata")?;
    ensure!(apps.len() <= MAX_APPS, "Too many application records");
    let mut labels = HashMap::with_capacity(apps.len());
    for app in apps {
        let package = app["package"].as_str().context("Missing package name")?;
        ensure!(
            !package.is_empty()
                && package.len() <= 255
                && package
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_')),
            "Invalid app metadata package name"
        );
        let uid = app["uid"].as_u64().context("Missing app UID")?;
        ensure!(uid < 100_000, "App metadata is not for the primary user");
        let label = app["label"].as_str().context("Missing application label")?;
        ensure!(
            label.len() <= 1024
                && label.chars().count() <= 256
                && !label.chars().any(char::is_control),
            "Invalid application label"
        );
        let system = app["system"].as_bool().context("Missing system-app flag")?;
        let metadata = AppMetadata {
            uid: uid as u32,
            label: if label.trim().is_empty() {
                package.to_string()
            } else {
                label.trim().to_string()
            },
            system,
        };
        ensure!(
            labels.insert(package.to_string(), metadata).is_none(),
            "Duplicate app metadata package"
        );
    }
    Ok(labels)
}

/// Avoid unbounded subprocess output and prevent an OEM service from hanging the HTTP server.
pub fn bounded_output(command: &mut Command, limit: usize, timeout: Duration) -> Result<Vec<u8>> {
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| -> Result<Vec<u8>> {
        let mut stdout = child.stdout.take().context("Missing subprocess output")?;
        let descriptor = stdout.as_raw_fd();
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        ensure!(
            flags >= 0
                && unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
            "Unable to configure subprocess output"
        );
        let deadline = Instant::now() + timeout;
        let mut output = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    if let Some(status) = child.try_wait()? {
                        ensure!(status.success(), "Android label command failed: {status}");
                        return Ok(output);
                    }
                }
                Ok(length) => {
                    ensure!(
                        length <= limit.saturating_sub(output.len()),
                        "Android command output exceeds limit"
                    );
                    output.extend_from_slice(&buffer[..length]);
                    ensure!(Instant::now() < deadline, "Android label command timed out");
                    continue;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
            ensure!(Instant::now() < deadline, "Android label command timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() {
        // pm can be a shell wrapper. Only terminate this helper's own process group.
        unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}
