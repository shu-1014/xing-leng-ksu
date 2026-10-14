# 星棱狐

An Android kernel root manager based on [KernelSU](https://github.com/tiann/KernelSU).
The Manager uses the `com.xinglinghu.su` application ID and the icon from the previous
星棱狐 APK. JNI and kernel/userspace interfaces retain their upstream namespaces.

[Chinese setup and usage](docs/README_CN.md) | [Web API](docs/星棱狐_WEB_API.md) |
[Migration and validation](docs/星棱狐_PLAN.md)

## Added features

- Configurable falling ikun images or snow, with size and speed controls.
- Launcher hiding with system phone dialer recovery: enter
  `*#*#917891786688#*#*`. No accessibility service or calculator setup is required.
- An authenticated local root web manager at `http://127.0.0.1:9178`, with app
  grants, kernel features, module ZIP installation/actions and SU logs.
- Matched GitHub Actions builds of Manager, ksud, ksuinit and kernel modules.

The feature controls are under Settings > 星棱狐 features. Dialer recovery uses
Android secret-code broadcasts; the system dialer must support this mechanism.
Some ROMs prevent automatic foreground launch, but the icon is still restored.
The web manager has Chinese status cards, named feature controls, and installed
application labels read from Android PackageManager, with package/UID details.

## GitHub Actions

Upload the complete source tree, including hidden `.github` files, to your repository.
Do not upload `private-signing`, keystores, the old reference APK, local build caches
or `dist`. The upload-ready source archive excludes those files.

Add four repository Actions secrets from your privately saved signing configuration:

| Secret | Value |
| --- | --- |
| `KEYSTORE` | Base64 of the permanent release JKS |
| `KEYSTORE_PASSWORD` | Store password |
| `KEY_ALIAS` | `ikunsu` |
| `KEY_PASSWORD` | Key password |

Locally generated private files are in the ignored `private-signing` directory.
Keep a separate backup of `ikunSU-release.jks`, `password.txt` and
`github-secrets.json`. The public certificate identity is safe to share.

Run **Build 星棱狐** from the Actions tab, or push to `main`, `master`, `dev` or `ci`.
Artifacts include `manager`, `ksud-<target>`, `ksuinit-<arch>` and
`<arch>-<kmi>-lkm`. The signing job derives the certificate hash and size, then passes
them to every kernel build so the module recognizes the Manager. The update
repository is automatically set to the repository running the workflow.

Without secrets, ordinary CI uses a temporary test key shared across that run's APK
and modules. It changes between runs. Release tags require the permanent secrets.
Push a `v*` tag to build and publish release artifacts after configuring the secrets.
Versions for Manager, ksud and the kernel come from `version.properties`:
`3.3.1-xinglinghu.1 / 32681`. This fork hotfix retains the upstream 3.3.1 core and UAPI 5.
Release builds reject missing embedded ko/ksuinit. The LKM workflow builds eight
KMI variants for AArch64 and x86_64, then collects all 16 modules as `lkm-all`.
Release publication requires an existing `v3.3.1-xinglinghu.1` tag matching the version file,
the permanent signing secrets, and a complete verified set of artifacts.

The newly generated signature differs from the previous APK. Android will require
uninstalling that APK before the first new installation. Preserve anything needed
from its app data first. Subsequent builds signed by this permanent key can upgrade
one another. Existing kernel modules must be rebuilt for the new certificate.

## Local builds

Use JDK 21 or newer, Android SDK 37.0, build tools 37.0.0 and NDK 29.0.14206865.
Windows Android builds need an ASCII checkout path. The native build includes the
repository's shared `uapi` directory directly, so archive symlink placeholders do
not prevent compilation.

After Rust source changes, run these checks in `userspace/ksud` in order:

Before the release build, stage the eight raw `<kmi>_kernelsu.ko` artifacts and
`ksuinit` from the same verified Actions build into `userspace/ksud/bin/aarch64/`.
Use the corresponding directory for x86_64; RISC-V requires only ksuinit because
the upstream LKM matrix has no RISC-V modules. If downloading renamed Release
modules, remove the `lkm-<arch>-` prefix before staging them. Verify them with
`python3 scripts/verify-embedded-assets.py --arch aarch64` from the repository root.

```sh
cargo ndk -t arm64-v8a check
cargo ndk -t arm64-v8a clippy
cargo fmt
cargo ndk -t arm64-v8a -P 26 build --release
```

Stage the fresh binary before running any Gradle task:

```sh
mkdir -p manager/app/src/main/jniLibs/arm64-v8a
cp target/aarch64-linux-android/release/ksud manager/app/src/main/jniLibs/arm64-v8a/libksud.so
cd manager
./gradlew clean assembleRelease lintRelease testDebugUnitTest -PKSU_ABIS=arm64-v8a
```

Pass signing properties through `ORG_GRADLE_PROJECT_KEYSTORE_FILE`,
`ORG_GRADLE_PROJECT_KEYSTORE_PASSWORD`, `ORG_GRADLE_PROJECT_KEY_ALIAS` and
`ORG_GRADLE_PROJECT_KEY_PASSWORD`. Without them the upstream signing plugin uses
its test signing fallback. A local Manager build only includes embedded kernel
modules/ksuinit if those assets were built and staged first; the full Actions
pipeline performs this staging automatically.

For a custom signing key, supply its certificate size and SHA-256 as
`KSU_EXPECTED_SIZE` and `KSU_EXPECTED_HASH` to ksud as well as the kernel build.
The web app-label helper checks that pin before loading the installed Manager.
The full Actions pipeline supplies both values from the actual APK signing key.

## Credits and licensing

KernelSU is the upstream implementation. CosmeticEdition and the previous 星棱狐
APK supplied visual/behavior references; the additional Compose effects and
dialer recovery are implemented for this source tree. Keep upstream copyright
notices and licenses. Kernel code is GPL-2.0-only; other components are
GPL-3.0-or-later. See [LICENSE](LICENSE) and [upstream documentation](docs/README.md).
# Authentication

See [the authentication walkthrough](docs/星棱狐_AUTHENTICATION.md) for Manager
certificate pinning, per-UID kernel authorization, local web bearer tokens, and
build credential handling.

