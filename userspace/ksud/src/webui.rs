//! Local web management. Authentication is required for every API request.
use crate::{defs, feature, feature_id::FeatureId, ksucalls, module};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Request, Response, Server};

const ADDRESS: &str = "127.0.0.1:9178";
const ORIGIN: &str = "http://127.0.0.1:9178";
const MAX_UPLOAD: u64 = 256 * 1024 * 1024;
const LAUNCHER: &str = "me.weishu.kernelsu.Launcher";

#[derive(clap::Subcommand, Debug)]
pub enum WebCommand {
    Start,
    Stop,
    /// Print the authenticated browser URL
    Url,
    /// Persist whether the service starts at boot
    Autostart {
        #[arg(value_parser = ["on", "off", "status"])]
        mode: String,
    },
    #[command(hide = true)]
    Serve,
    /// Internal root-only subprocess; the server keeps its original credentials.
    #[command(hide = true)]
    Grant {
        package: String,
        uid: i32,
        #[arg(long, action = clap::ArgAction::Set)]
        granted: bool,
    },
}

fn path(name: &str) -> std::path::PathBuf {
    Path::new(defs::WORKING_DIR).join(name)
}
pub fn autostart_enabled() -> bool {
    path("webui.autostart").exists()
}

fn prepare_directory() -> Result<()> {
    fs::create_dir_all(defs::WORKING_DIR)?;
    let metadata = fs::symlink_metadata(defs::WORKING_DIR)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "Web manager directory must be owned by root and not writable by other users"
    );
    Ok(())
}

fn random_token() -> Result<String> {
    let mut random = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(base16ct::lower::encode_string(&random))
}

fn write_private(name: &str, value: &str) -> Result<()> {
    let temporary = path(&format!(
        "{name}.{}.{}",
        std::process::id(),
        random_token()?
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        ensure!(
            file.metadata()?.uid() == 0,
            "Web manager credentials must be owned by root"
        );
        file.write_all(value.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path(name))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn read_private(name: &str) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path(name))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o777 == 0o600
            && metadata.len() <= 128,
        "Invalid ownership, permissions, or size for {name}"
    );
    let mut value = String::new();
    file.take(129).read_to_string(&mut value)?;
    ensure!(value.len() <= 128, "Invalid size for {name}");
    Ok(value)
}

fn live_token() -> Result<String> {
    // A process that merely binds port 9178 must receive no credentials.
    let pid = crate::webui_auth::server_pid(&read_private("webui.pid")?)
        .context("Invalid web manager PID")?;
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(
        crate::webui_auth::root_server_process(&status, &cmdline),
        "No authenticated root web manager is running"
    );
    let value = read_private("webui.token")?;
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Invalid web token"
    );
    Ok(value)
}

struct ServerIdentity {
    pid: u32,
}

impl ServerIdentity {
    fn publish() -> Result<Self> {
        let pid = std::process::id();
        write_private("webui.pid", &format!("{pid}\n"))?;
        Ok(Self { pid })
    }
}

impl Drop for ServerIdentity {
    fn drop(&mut self) {
        if read_private("webui.pid")
            .ok()
            .and_then(|value| crate::webui_auth::server_pid(&value))
            == Some(self.pid)
        {
            let _ = fs::remove_file(path("webui.pid"));
        }
    }
}

fn control(endpoint: &str) -> Result<()> {
    let secret = live_token()?;
    let mut stream = TcpStream::connect_timeout(&ADDRESS.parse()?, Duration::from_secs(1))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "POST {endpoint} HTTP/1.1\r\nHost: {ADDRESS}\r\nAuthorization: Bearer {secret}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    let mut reply = String::new();
    stream.take(4096).read_to_string(&mut reply)?;
    ensure!(
        reply.starts_with("HTTP/1.1 200"),
        "Web manager did not accept the request"
    );
    Ok(())
}

fn installed_daemon() -> Result<&'static str> {
    let metadata = fs::symlink_metadata(defs::DAEMON_PATH)
        .context("Install or update ksud from the Manager before starting the web service")?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
            && metadata.len() > 0,
        "Installed ksud must be a root-owned, protected executable file"
    );
    Ok(defs::DAEMON_PATH)
}

fn process_identity(stat: &str) -> Option<(u64, bool)> {
    // The parenthesized comm field may contain spaces or closing parentheses.
    let (_, fields) = stat.rsplit_once(')')?;
    let mut fields = fields.split_whitespace();
    let state = fields.next()?;
    // starttime is field 22; state above is field 3.
    let starttime = fields.nth(18)?.parse().ok()?;
    Some((starttime, state != "Z" && state != "X"))
}

fn wait_for_shutdown(pid: u32, starttime: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let address = ADDRESS.parse()?;
    loop {
        let exited = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => {
                let (current_starttime, running) =
                    process_identity(&stat).context("Invalid web manager process status")?;
                current_starttime != starttime || !running
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(error).context("Cannot inspect the previous web manager"),
        };
        let released = match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            Ok(stream) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                false
            }
            Err(error) => error.kind() == std::io::ErrorKind::ConnectionRefused,
        };
        if exited && released {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "Previous web manager did not stop or release port 9178; open the Manager, stop its web service, then retry"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn start() -> Result<()> {
    if control("/api/ping").is_ok() {
        let pid = crate::webui_auth::server_pid(&read_private("webui.pid")?)
            .context("Invalid web manager PID")?;
        let running = fs::metadata(format!("/proc/{pid}/exe"))?;
        let installed = fs::metadata(installed_daemon()?)?;
        if running.dev() == installed.dev() && running.ino() == installed.ino() {
            return Ok(());
        }
        let (starttime, _) = process_identity(&fs::read_to_string(format!("/proc/{pid}/stat"))?)
            .context("Invalid web manager process status")?;
        // An APK/daemon update must not silently keep the previous server alive.
        control("/api/shutdown")?;
        // The HTTP acknowledgement precedes shutdown, and tiny_http closes its
        // listener on another thread. Wait for both before binding a new one.
        wait_for_shutdown(pid, starttime)?;
    } else if live_token().is_ok() {
        bail!(
            "Existing root web manager is not responding; open the Manager to unfreeze it, stop its web service, then retry"
        );
    }
    prepare_directory()?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path("webui.log"))?;
    ensure!(
        log.metadata()?.uid() == 0,
        "Web manager log must be owned by root"
    );
    log.set_permissions(fs::Permissions::from_mode(0o600))?;
    // Use the installed executable, whose path survives APK replacement and
    // launcher changes. The Manager installs its current daemon on startup.
    let mut child = Command::new(installed_daemon()?);
    child
        .args(["webui", "serve"])
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    unsafe {
        child.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = child
        .spawn()
        .context("Failed to start the installed web manager daemon")?;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if control("/api/ping").is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!(
                "Installed ksud web manager exited with {status}; update ksud and check /data/adb/ksu/webui.log"
            );
        }
    }
    bail!("Web manager failed to start; check /data/adb/ksu/webui.log (port 9178 may be in use)")
}

pub fn run(command: WebCommand) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Root is required for the web manager"
    );
    match command {
        WebCommand::Start => start(),
        WebCommand::Stop => control("/api/shutdown"),
        WebCommand::Url => {
            println!("{ORIGIN}/#{}", live_token()?);
            Ok(())
        }
        WebCommand::Autostart { mode } => {
            match mode.as_str() {
                "on" => {
                    prepare_directory()?;
                    fs::write(path("webui.autostart"), b"1")?;
                }
                "off" => {
                    if autostart_enabled() {
                        fs::remove_file(path("webui.autostart"))?;
                    }
                }
                _ => println!("{}", autostart_enabled()),
            }
            Ok(())
        }
        WebCommand::Serve => serve(),
        WebCommand::Grant {
            package,
            uid,
            granted,
        } => set_grant_as_manager(&package, uid, granted),
    }
}

fn set_grant_as_manager(package: &str, uid: i32, granted: bool) -> Result<()> {
    ensure!(
        unsafe { libc::getuid() } == 0,
        "Root is required for the grant helper"
    );
    let manager = ksucalls::manager_appid()?;
    ensure!(
        (10_000..100_000).contains(&manager),
        "No authenticated Manager is installed"
    );
    let packages = fs::read_to_string("/data/system/packages.list")?;
    let package_uid = |name: &str| {
        packages.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == name)
                .then(|| fields.next()?.parse::<u32>().ok())
                .flatten()
        })
    };
    ensure!(
        package_uid(defs::DEFAULT_PACKAGE_NAME) == Some(manager),
        "Manager UID does not match the kernel identity"
    );
    ensure!(
        u32::try_from(uid).is_ok_and(|uid| package_uid(package) == Some(uid)),
        "Package/UID mismatch"
    );
    // GET/SET_APP_PROFILE requires the Manager's real UID. This short-lived
    // helper keeps effective/saved UID 0, and changes no server-thread identity.
    ensure!(
        unsafe { libc::setresuid(manager, 0, 0) } == 0,
        "Cannot assume the authenticated Manager UID: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        unsafe { libc::getuid() } == manager && unsafe { libc::geteuid() } == 0,
        "Unexpected grant helper credentials"
    );
    ksucalls::set_default_app_grant(package, uid, granted)
}

fn header<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

fn serve() -> Result<()> {
    // setsid only detaches the process group; Android can still kill the whole
    // Manager cgroup when its launcher component changes. Move this process
    // before creating HTTP worker threads, as for the existing root shell.
    crate::utils::switch_cgroups();
    ksucalls::ensure_uapi_version_matched()?;
    crate::utils::switch_mnt_ns(1)?;
    let server = Server::http(ADDRESS).map_err(|e| anyhow::anyhow!("{e}"))?;
    prepare_directory()?;
    // Rotate only after binding. A failed start must never create a token that
    // a fake listener can capture and replay against a future root service.
    let secret = random_token()?;
    write_private("webui.token", &secret)?;
    // Dropped before Server, withdrawing the PID before releasing its socket.
    let _identity = ServerIdentity::publish()?;
    for mut request in server.incoming_requests() {
        let endpoint = request.url().split('?').next().unwrap_or("").to_owned();
        let authenticated = header(&request, "Authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            == Some(secret.as_str());
        let allowed = crate::webui_auth::allowed(
            header(&request, "Host"),
            header(&request, "Origin"),
            header(&request, "Authorization"),
            &secret,
            endpoint == "/",
        );
        let (status, mime, body) = if !allowed {
            (
                403,
                "application/json",
                json!({"error":"Access denied; open the URL from 星棱狐"}).to_string(),
            )
        } else if endpoint == "/" && request.method() == &Method::Get {
            (
                200,
                "text/html; charset=utf-8",
                include_str!("webui.html").to_owned(),
            )
        } else {
            match dispatch(&mut request, &endpoint) {
                Ok(value) => (200, "application/json", value.to_string()),
                Err(err) => (
                    400,
                    "application/json",
                    json!({"error":format!("{err:#}")}).to_string(),
                ),
            }
        };
        let shutdown = status == 200 && endpoint == "/api/shutdown" && authenticated;
        let mut response = Response::from_string(body).with_status_code(status);
        for (name, value) in [
            ("Content-Type", mime),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Frame-Options", "DENY"),
        ] {
            response.add_header(
                Header::from_bytes(name, value)
                    .map_err(|()| anyhow::anyhow!("Invalid response header"))?,
            );
        }
        if let Err(e) = request.respond(response) {
            log::warn!("Web response failed: {e}");
        }
        if shutdown {
            break;
        }
    }
    Ok(())
}

fn command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn apps() -> Result<Vec<Value>> {
    let packages = fs::read_to_string("/data/system/packages.list")?;
    let labels = crate::webui_apps::labels();
    packages
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let package = fields.next().context("Missing package")?;
            let uid: u32 = fields.next().context("Missing UID")?.parse()?;
            let metadata = labels.get(package).filter(|metadata| metadata.uid == uid);
            Ok(json!({
                "package": package,
                "uid": uid,
                "label": metadata.map_or(package, |metadata| metadata.label.as_str()),
                "system": metadata.map(|metadata| metadata.system),
                "granted": ksucalls::uid_granted_root(uid)?
            }))
        })
        .collect()
}

fn stealth() -> Result<bool> {
    let dump = command(
        "/system/bin/dumpsys",
        &["package", defs::DEFAULT_PACKAGE_NAME],
    )?;
    let mut system_user = false;
    let mut disabled = false;
    for line in dump.lines().map(str::trim) {
        if line.starts_with("User ") {
            system_user = line.starts_with("User 0:");
            disabled = false;
        }
        if system_user && line == "disabledComponents:" {
            disabled = true;
            continue;
        }
        if disabled && line == LAUNCHER {
            return Ok(true);
        }
        if disabled && line.contains(':') {
            disabled = false;
        }
    }
    Ok(false)
}

fn set_stealth(enabled: bool) -> Result<()> {
    if enabled {
        crate::stealth::start()?;
        // Policy changes prevent future freezes but cannot thaw an existing one.
        // Only terminate the verified frozen Manager, preserving launchability.
        if let Err(error) = crate::stealth::clear_frozen_manager() {
            crate::stealth::restore_launcher()?;
            return Err(error).context("Cannot clear the frozen Manager before hiding");
        }
    }
    let component = format!("{}/{LAUNCHER}", defs::DEFAULT_PACKAGE_NAME);
    command(
        "/system/bin/pm",
        &[
            if enabled { "disable" } else { "enable" },
            "--user",
            "0",
            &component,
        ],
    )?;
    if !enabled {
        let _ = crate::stealth::stop();
    }
    Ok(())
}

fn dispatch(request: &mut Request, endpoint: &str) -> Result<Value> {
    let read_only = [
        "/api/status",
        "/api/features",
        "/api/apps",
        "/api/superuser",
        "/api/modules",
        "/api/su_log_dump",
    ];
    ensure!(
        request.method() == &Method::Post
            || (request.method() == &Method::Get && read_only.contains(&endpoint)),
        "POST is required for changes"
    );
    if endpoint == "/api/module_install" {
        ensure!(
            request
                .body_length()
                .is_some_and(|n| n > 0 && n as u64 <= MAX_UPLOAD),
            "ZIP must be at most 256 MiB"
        );
        ensure!(
            header(request, "Content-Type") == Some("application/zip"),
            "Send the ZIP as application/zip"
        );
        let mut file = tempfile::Builder::new()
            .suffix(".zip")
            .tempfile_in(defs::WORKING_DIR)?;
        let expected = request.body_length().context("Missing upload size")? as u64;
        let copied = std::io::copy(&mut request.as_reader().take(MAX_UPLOAD + 1), &mut file)?;
        ensure!(
            copied == expected && copied <= MAX_UPLOAD,
            "Incomplete upload"
        );
        file.flush()?;
        module::install_module(file.path().to_str().context("Invalid upload path")?)?;
        return Ok(json!({"ok":true}));
    }
    let mut body = String::new();
    request
        .as_reader()
        .take(16 * 1024 + 1)
        .read_to_string(&mut body)?;
    ensure!(body.len() <= 16 * 1024, "Request too large");
    let args: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_str(&body)?
    };
    match endpoint {
        "/api/ping" | "/api/shutdown" => Ok(json!({"ok":true})),
        "/api/status" => Ok(
            json!({"name":"星棱狐","version":defs::VERSION_NAME,"kernel":ksucalls::get_version(),"mode":ksucalls::runtime_mode(),"stealth":stealth()?,"webui_autostart":autostart_enabled()}),
        ),
        "/api/features" => {
            let managed = module::get_managed_features()?;
            let items: Vec<_> = FeatureId::ALL.iter().map(|id| {
                let state = ksucalls::get_feature(*id as u32).unwrap_or_default();
                json!({"name":id.name(),"enabled":state.value != 0,"supported":state.supported,"forced":state.forced,"managed":managed.values().any(|v| v.iter().any(|s| s == id.name()))})
            }).collect();
            Ok(json!(items))
        }
        "/api/apps" => Ok(json!(apps()?)),
        "/api/superuser" => Ok(json!(
            apps()?
                .into_iter()
                .filter(|app| app["granted"] == true)
                .collect::<Vec<_>>()
        )),
        "/api/modules" => Ok(serde_json::from_str(&command(
            defs::DAEMON_PATH,
            &["module", "list"],
        )?)?),
        "/api/superuser_toggle" => {
            let package = args["package"].as_str().context("Missing package")?;
            let uid = args["uid"].as_u64().context("Missing UID")?;
            ensure!(
                apps()?
                    .iter()
                    .any(|v| v["package"] == package && v["uid"] == uid),
                "Package/UID mismatch"
            );
            let uid = i32::try_from(uid)?.to_string();
            let granted = args["granted"].as_bool().context("Missing granted")?;
            command(
                installed_daemon()?,
                &[
                    "webui",
                    "grant",
                    package,
                    &uid,
                    "--granted",
                    if granted { "true" } else { "false" },
                ],
            )?;
            Ok(json!({"ok":true}))
        }
        "/api/feature_toggle" => {
            let name = args["name"].as_str().context("Missing feature")?;
            let enabled = args["enabled"].as_bool().context("Missing enabled")?;
            match name {
                "stealth" => set_stealth(enabled)?,
                "webui_autostart" => run(WebCommand::Autostart {
                    mode: if enabled { "on" } else { "off" }.to_owned(),
                })?,
                _ => {
                    feature::set_feature(name, u64::from(enabled))?;
                    feature::save_config()?;
                }
            }
            Ok(json!({"ok":true}))
        }
        "/api/feature_save" => {
            feature::save_config()?;
            Ok(json!({"ok":true}))
        }
        "/api/module_action" => {
            let id = args["id"].as_str().context("Missing module ID")?;
            module::validate_module_id(id)?;
            match args["act"].as_str().context("Missing action")? {
                "enable" => module::enable_module(id)?,
                "disable" => module::disable_module(id)?,
                "uninstall" => module::uninstall_module(id)?,
                "undo" => module::undo_uninstall_module(id)?,
                "action" => module::run_action(id)?,
                _ => bail!("Unknown module action"),
            }
            Ok(json!({"ok":true}))
        }
        "/api/su_log_dump" => {
            let mut logs: Vec<_> = fs::read_dir(defs::LOG_DIR)?
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name().is_some_and(|n| {
                        n.to_string_lossy().starts_with("sulog-")
                            && n.to_string_lossy().ends_with(".log")
                    })
                })
                .collect();
            logs.sort();
            let log = if let Some(latest) = logs.last() {
                use std::io::{Seek, SeekFrom};
                let mut file = File::open(latest)?;
                let length = file.metadata()?.len();
                file.seek(SeekFrom::Start(length.saturating_sub(256 * 1024)))?;
                let mut bytes = Vec::new();
                file.take(256 * 1024).read_to_end(&mut bytes)?;
                String::from_utf8_lossy(&bytes).into_owned()
            } else {
                String::new()
            };
            Ok(json!({"log":log}))
        }
        _ => bail!("Unknown API endpoint"),
    }
}
