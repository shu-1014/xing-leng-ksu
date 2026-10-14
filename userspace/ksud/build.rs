use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const BOOTSTRAP_SOURCE: &str = "src/lkm_image_bootstrap.S";
const BOOTSTRAP_OBJECT: &str = "lkm_image_bootstrap.o";
const PREPARED_BOOTSTRAP_OBJECT: &str = ".lkm_image_bootstrap.o";

fn release_version() -> (u32, String) {
    let path = Path::new("../../version.properties");
    println!("cargo:rerun-if-changed={}", path.display());
    let contents = fs::read_to_string(path).expect("cannot read shared version.properties");
    let property = |key: &str| {
        contents
            .lines()
            .filter_map(|line| line.split_once('='))
            .find(|(name, _)| name.trim() == key)
            .map(|(_, value)| value.trim().to_string())
            .unwrap_or_else(|| panic!("missing {key} in version.properties"))
    };
    (
        property("KSU_VERSION_CODE")
            .parse()
            .expect("invalid KSU_VERSION_CODE"),
        property("KSU_VERSION_NAME"),
    )
}

fn manager_certificate() {
    println!("cargo:rerun-if-env-changed=KSU_EXPECTED_SIZE");
    println!("cargo:rerun-if-env-changed=KSU_EXPECTED_HASH");
    let size = env::var("KSU_EXPECTED_SIZE").unwrap_or_else(|_| "878".to_string());
    let size = if let Some(hex) = size.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else {
        size.parse::<u32>()
    }
    .expect("invalid KSU_EXPECTED_SIZE");
    assert!(
        (1..=1024).contains(&size),
        "invalid Manager certificate size"
    );
    let hash = env::var("KSU_EXPECTED_HASH").unwrap_or_else(|_| {
        "f00129f638639a1d41cb71d4f3e63c25b3a87127ac8eb038dd74ca0774d05c5f".to_string()
    });
    assert!(
        hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid KSU_EXPECTED_HASH"
    );
    println!("cargo:rustc-env=KSU_EXPECTED_SIZE={size}");
    println!(
        "cargo:rustc-env=KSU_EXPECTED_HASH={}",
        hash.to_ascii_lowercase()
    );
}

fn validate_release_assets() {
    // Debug check/Clippy may run before the kernel matrix is built. A release
    // must embed every supported KMI and ksuinit for its target architecture.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("android") {
        return;
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("missing target architecture");
    let machine = match arch.as_str() {
        "aarch64" => 183,
        "x86_64" => 62,
        "riscv64" => 243,
        _ => panic!("unsupported Android architecture: {arch}"),
    };
    let directory = PathBuf::from("bin").join(&arch);
    println!("cargo:rerun-if-changed={}", directory.display());
    if env::var("PROFILE").as_deref() != Ok("release") {
        return;
    }
    let targets_path = Path::new("../../scripts/lkm-targets.json");
    println!("cargo:rerun-if-changed={}", targets_path.display());
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(targets_path).expect("cannot read LKM target manifest"),
    )
    .expect("invalid LKM target manifest");
    let mut files = vec![("ksuinit".to_string(), false)];
    if arch != "riscv64" {
        for kmi in manifest["kmis"].as_array().expect("missing KMI list") {
            files.push((format!("{}_kernelsu.ko", kmi.as_str().unwrap()), true));
        }
    }
    for (name, module) in files {
        let path = directory.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "release asset {} is missing: {error}; build/stage LKM and ksuinit before ksud",
                path.display()
            )
        });
        let valid = bytes.len() >= 64
            && bytes.starts_with(b"\x7fELF")
            && bytes[4] == 2
            && bytes[5] == 1
            && u16::from_le_bytes([bytes[18], bytes[19]]) == machine;
        assert!(valid, "invalid ELF architecture for {}", path.display());
        let kind = u16::from_le_bytes([bytes[16], bytes[17]]);
        assert!(
            if module {
                kind == 1
            } else {
                kind == 2 || kind == 3
            },
            "invalid ELF type for {}",
            path.display()
        );
    }
}

fn configure_bindgen() {
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let mut builder = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/ksu_uapi.h")
        .clang_args(["-x", "c++", "-I../../"])
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("riscv64") {
        // libc does not yet expose Android's RISC-V signal context. Generate
        // it from the target NDK rather than assuming another libc's layout.
        builder = builder.header_contents("ksu_signal_context.h", "#include <sys/ucontext.h>");
    }
    let bindings = builder
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = std::path::PathBuf::from(env::var("OUT_DIR").unwrap());
    // for debug, uncomment below
    // let out_path = std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn validate_bootstrap_object(path: &Path) -> io::Result<()> {
    let object = fs::read(path)?;
    let valid = object.len() >= 64
        && object.starts_with(b"\x7fELF")
        && object[4] == 2
        && object[5] == 1
        && u16::from_le_bytes([object[16], object[17]]) == 1
        && u16::from_le_bytes([object[18], object[19]]) == 183;
    if valid {
        Ok(())
    } else {
        Err(io::Error::other(
            "bootstrap object must be a little-endian AArch64 ELF64 ET_REL",
        ))
    }
}

fn copy_bootstrap_object(source: &Path, output: &Path) -> io::Result<()> {
    validate_bootstrap_object(source)?;
    fs::copy(source, output)?;
    Ok(())
}

fn ndk_clang() -> Option<PathBuf> {
    let ndk = env::var_os("ANDROID_NDK_HOME")
        .or_else(|| env::var_os("ANDROID_NDK_ROOT"))
        .map(PathBuf::from)?;
    let prebuilt = ndk.join("toolchains/llvm/prebuilt");
    let mut hosts = fs::read_dir(prebuilt)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    hosts.sort();
    hosts.into_iter().find_map(|host| {
        ["clang", "clang.exe"]
            .into_iter()
            .map(|name| host.join("bin").join(name))
            .find(|path| path.is_file())
    })
}

fn run_assembler(program: &Path, arguments: &[OsString]) -> Result<(), String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("{}: {error}", program.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let details = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    Err(format!(
        "{}: {}",
        program.display(),
        String::from_utf8_lossy(details).trim()
    ))
}

fn assemble_bootstrap() {
    println!("cargo:rerun-if-changed={BOOTSTRAP_SOURCE}");
    println!("cargo:rerun-if-env-changed=KSU_LKM_BOOTSTRAP_OBJECT");
    println!("cargo:rerun-if-env-changed=KSU_LKM_BOOTSTRAP_CC");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_ROOT");

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest.join(BOOTSTRAP_SOURCE);
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join(BOOTSTRAP_OBJECT);

    if let Some(prebuilt) = env::var_os("KSU_LKM_BOOTSTRAP_OBJECT") {
        let prebuilt = PathBuf::from(prebuilt);
        copy_bootstrap_object(&prebuilt, &output).unwrap_or_else(|error| {
            panic!(
                "cannot use KSU_LKM_BOOTSTRAP_OBJECT {}: {error}",
                prebuilt.display()
            )
        });
        return;
    }

    // cross builds prepare this file on the host before entering the container.
    let prepared = manifest.join(PREPARED_BOOTSTRAP_OBJECT);
    println!("cargo:rerun-if-changed={}", prepared.display());
    if prepared.is_file() {
        copy_bootstrap_object(&prepared, &output).unwrap_or_else(|error| {
            panic!(
                "cannot use prepared bootstrap object {}: {error}",
                prepared.display()
            )
        });
        return;
    }

    let mut errors = Vec::new();
    let mut drivers = Vec::<PathBuf>::new();
    if let Some(compiler) = env::var_os("KSU_LKM_BOOTSTRAP_CC") {
        drivers.push(PathBuf::from(compiler));
    }
    drivers.push(PathBuf::from("aarch64-linux-gnu-gcc"));
    if let Some(clang) = ndk_clang() {
        drivers.push(clang);
    }
    drivers.push(PathBuf::from("clang"));

    for driver in drivers {
        let mut arguments = Vec::<OsString>::new();
        if driver
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains("clang"))
        {
            arguments.push("--target=aarch64-linux-gnu".into());
        }
        arguments.extend([
            "-c".into(),
            "-nostdlib".into(),
            "-o".into(),
            output.as_os_str().to_owned(),
            source.as_os_str().to_owned(),
        ]);
        match run_assembler(&driver, &arguments) {
            Ok(()) => {
                validate_bootstrap_object(&output)
                    .expect("assembler produced an invalid bootstrap object");
                return;
            }
            Err(error) => errors.push(error),
        }
    }

    let llvm_mc = PathBuf::from("llvm-mc");
    let llvm_arguments = [
        "-triple=aarch64-linux-gnu".into(),
        "-filetype=obj".into(),
        "-o".into(),
        output.as_os_str().to_owned(),
        source.as_os_str().to_owned(),
    ];
    match run_assembler(&llvm_mc, &llvm_arguments) {
        Ok(()) => {
            validate_bootstrap_object(&output)
                .expect("llvm-mc produced an invalid bootstrap object");
        }
        Err(error) => {
            errors.push(error);
            panic!(
                "cannot assemble the AArch64 LKM bootstrap; install an AArch64 GNU compiler, clang, or llvm-mc, or set KSU_LKM_BOOTSTRAP_OBJECT:\n{}",
                errors.join("\n")
            );
        }
    }
}

fn main() {
    assemble_bootstrap();

    let (code, name) = release_version();
    manager_certificate();
    validate_release_assets();
    if env::var("KSU_PACKAGE_NAME").is_err() {
        println!("cargo:rustc-env=KSU_PACKAGE_NAME=com.xinglinghu.su");
    }
    println!("cargo:rerun-if-env-changed=KSU_PACKAGE_NAME");
    println!("cargo:rustc-env=VERSION_CODE={code}");
    println!("cargo:rustc-env=VERSION_NAME={name}");

    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS not set");
    if target_os == "android" {
        configure_bindgen();
    }
}
