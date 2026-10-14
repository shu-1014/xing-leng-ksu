//! Shared request authorization rules for the local root web manager.

pub fn server_pid(value: &str) -> Option<u32> {
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u32>().ok().filter(|pid| *pid > 1)
}

pub fn root_server_process(status: &str, cmdline: &[u8]) -> bool {
    let mut uid_lines = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let Some(uid_line) = uid_lines.next() else {
        return false;
    };
    let uids = uid_line
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>();
    let effective_root = uids.is_ok_and(|uids| uids.len() == 4 && uids[1] == 0);
    if !effective_root || uid_lines.next().is_some() {
        return false;
    }
    let Some(cmdline) = cmdline.strip_suffix(&[0]) else {
        return false;
    };
    let arguments = cmdline.split(|byte| *byte == 0).collect::<Vec<_>>();
    arguments.len() == 3
        && !arguments[0].is_empty()
        && arguments[1] == b"webui"
        && arguments[2] == b"serve"
}

pub fn allowed(
    host: Option<&str>,
    origin: Option<&str>,
    authorization: Option<&str>,
    secret: &str,
    public_page: bool,
) -> bool {
    host == Some("127.0.0.1:9178")
        && origin.is_none_or(|value| value == "http://127.0.0.1:9178")
        && (public_page
            || authorization.and_then(|value| value.strip_prefix("Bearer ")) == Some(secret))
}

#[cfg(test)]
mod tests {
    use super::{allowed, root_server_process, server_pid};
    #[test]
    fn pid_file_requires_one_valid_process_id() {
        assert_eq!(server_pid("12345"), Some(12345));
        assert_eq!(server_pid("12345\n"), Some(12345));
        for malformed in [
            "",
            "0",
            "1",
            "-1",
            "12345 67890",
            "12345\n67890",
            " 12345",
            "4294967296",
        ] {
            assert_eq!(server_pid(malformed), None, "{malformed:?}");
        }
    }
    #[test]
    fn accepts_only_a_root_webui_serve_process() {
        let status = "Name:\tksud\nUid:\t0\t0\t0\t0\n";
        assert!(root_server_process(
            status,
            b"/data/adb/ksud\0webui\0serve\0"
        ));
        assert!(root_server_process(
            status,
            b"/data/app/com.xinglinghu.su/lib/arm64/libksud.so\0webui\0serve\0"
        ));
        for command in [
            &b"/data/adb/ksud\0webui\0start\0"[..],
            &b"/data/adb/ksud\0webui\0serve\0extra\0"[..],
            &b"/data/adb/ksud\0webui\0serve"[..],
            &b"\0webui\0serve\0"[..],
            &b"/data/adb/ksud webui serve\0"[..],
        ] {
            assert!(!root_server_process(status, command));
        }
    }
    #[test]
    fn rejects_nonroot_reused_or_malformed_pid_status() {
        let command = b"/data/adb/ksud\0webui\0serve\0";
        for status in [
            "Name:\tksud\nUid:\t10000\t10000\t10000\t10000\n",
            "Name:\tksud\nUid:\t0\t10000\t0\t0\n",
            "Name:\tksud\n",
            "Uid:\t0\t0\t0\n",
            "Uid:\t0\t0\tbad\t0\n",
            "Uid:\t0\t0\t0\t0\nUid:\t0\t0\t0\t0\n",
        ] {
            assert!(!root_server_process(status, command), "{status:?}");
        }
    }
    #[test]
    fn restarting_rejects_the_previous_browser_token() {
        let old_token = "old_session_token";
        let new_token = "new_session_token";
        assert!(!allowed(
            Some("127.0.0.1:9178"),
            None,
            Some(&format!("Bearer {old_token}")),
            new_token,
            false
        ));
        assert!(allowed(
            Some("127.0.0.1:9178"),
            None,
            Some(&format!("Bearer {new_token}")),
            new_token,
            false
        ));
    }
    #[test]
    fn rejects_cross_origin_and_rebound_hosts_even_with_a_token() {
        assert!(!allowed(
            Some("attacker.example:9178"),
            None,
            Some("Bearer secret"),
            "secret",
            false
        ));
        assert!(!allowed(
            Some("127.0.0.1:9178"),
            Some("https://attacker.example"),
            Some("Bearer secret"),
            "secret",
            false
        ));
        assert!(!allowed(
            Some("127.0.0.1:9178"),
            Some("null"),
            Some("Bearer secret"),
            "secret",
            false
        ));
    }
    #[test]
    fn api_requires_an_exact_token_but_the_login_page_can_load() {
        assert!(!allowed(
            Some("127.0.0.1:9178"),
            None,
            None,
            "secret",
            false
        ));
        assert!(!allowed(
            Some("127.0.0.1:9178"),
            None,
            Some("Bearer wrong"),
            "secret",
            false
        ));
        assert!(allowed(
            Some("127.0.0.1:9178"),
            None,
            Some("Bearer secret"),
            "secret",
            false
        ));
        assert!(allowed(Some("127.0.0.1:9178"), None, None, "secret", true));
    }
}
