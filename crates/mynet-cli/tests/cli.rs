use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn mynet_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mynet")
}

fn run_in(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(mynet_bin())
        .env("MYNET_CONFIG_DIR", dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run mynet {args:?}: {e}"))
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn help_exits_zero_and_lists_version() {
    let output = Command::new(mynet_bin())
        .arg("--help")
        .output()
        .expect("failed to run mynet --help");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("Usage:"), "unexpected help:\n{stdout}");
    assert!(stdout.contains("peer"));
    assert!(stdout.contains("version"));
    assert!(stdout.contains("init"));
    assert!(stdout.contains("identity"));
    assert!(stdout.contains("peer"));
    assert!(stdout.contains("connect"));
    assert!(stdout.contains("start"));
    assert!(stdout.contains("tun-test"));
    assert!(stdout.contains("export"));
}

#[test]
fn version_flag_prints_package_version() {
    let output = Command::new(mynet_bin())
        .arg("--version")
        .output()
        .expect("failed to run mynet --version");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("0.1.0"), "unexpected --version: {stdout:?}");
}

#[test]
fn version_subcommand_prints_package_version() {
    let output = Command::new(mynet_bin())
        .arg("version")
        .output()
        .expect("failed to run mynet version");
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(
        stdout.contains("mynet 0.1.0"),
        "unexpected version output: {stdout:?}"
    );
}

#[test]
fn init_then_identity_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let init = run_in(dir.path(), &["init"]);
    assert!(init.status.success(), "stderr: {}", stderr(&init));
    let created = stdout(&init);
    assert!(created.contains("Peer ID:"));
    assert!(created.contains("Public Key:"));
    assert!(!created.to_lowercase().contains("private key"));

    let shown = run_in(dir.path(), &["identity"]);
    assert!(shown.status.success(), "stderr: {}", stderr(&shown));
    assert_eq!(
        extract_line(&stdout(&init), "Peer ID:"),
        extract_line(&stdout(&shown), "Peer ID:")
    );
    assert_eq!(
        extract_line(&stdout(&init), "Public Key:"),
        extract_line(&stdout(&shown), "Public Key:")
    );
}

#[test]
fn identity_without_init_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let shown = run_in(dir.path(), &["identity"]);
    assert!(!shown.status.success());
    let err = format!("{}{}", stdout(&shown), stderr(&shown));
    assert!(err.contains("not found") || err.contains("mynet init"), "{err}");
}

#[test]
fn init_refuses_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    assert!(run_in(dir.path(), &["init"]).status.success());
    let first = run_in(dir.path(), &["identity"]);
    let first_id = extract_line(&stdout(&first), "Peer ID:").to_string();

    let second = run_in(dir.path(), &["init"]);
    assert!(!second.status.success());
    let err = format!("{}{}", stdout(&second), stderr(&second));
    assert!(err.contains("--force"), "{err}");

    let still = run_in(dir.path(), &["identity"]);
    assert_eq!(extract_line(&stdout(&still), "Peer ID:"), first_id);
}

#[test]
fn two_config_dirs_get_independent_identities() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    assert!(run_in(a.path(), &["init"]).status.success());
    assert!(run_in(b.path(), &["init"]).status.success());
    let id_a = extract_line(&stdout(&run_in(a.path(), &["identity"])), "Public Key:").to_string();
    let id_b = extract_line(&stdout(&run_in(b.path(), &["identity"])), "Public Key:").to_string();
    assert_ne!(id_a, id_b);
}

fn extract_line<'a>(text: &'a str, prefix: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::trim))
        .unwrap_or_else(|| panic!("missing {prefix:?} in:\n{text}"))
}

#[test]
fn malformed_identity_file_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.toml");
    fs::write(&path, "not-an-identity").unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms).unwrap();
    let shown = run_in(dir.path(), &["identity"]);
    assert!(!shown.status.success());
    let err = format!("{}{}", stdout(&shown), stderr(&shown));
    assert!(err.contains("malformed"), "{err}");
}

#[test]
fn peer_add_list_remove() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());
    let bob_pk = extract_line(&stdout(&run_in(bob.path(), &["identity"])), "Public Key:").to_string();

    let add = run_in(
        alice.path(),
        &[
            "peer",
            "add",
            "--public-key",
            &bob_pk,
            "--ip",
            "10.42.0.2",
            "--endpoint",
            "192.0.2.10:51820",
            "--name",
            "bob",
        ],
    );
    assert!(add.status.success(), "stderr: {}", stderr(&add));
    let listed = run_in(alice.path(), &["peer", "list"]);
    assert!(listed.status.success(), "stderr: {}", stderr(&listed));
    let listed_out = stdout(&listed);
    assert!(listed_out.contains("bob"));
    assert!(listed_out.contains("10.42.0.2"));
    assert!(listed_out.contains("192.0.2.10:51820"));
    assert!(listed_out.contains("disconnected"));
    assert!(listed_out.contains(&bob_pk));

    let dup = run_in(
        alice.path(),
        &["peer", "add", "--public-key", &bob_pk, "--ip", "10.42.0.3"],
    );
    assert!(!dup.status.success());

    let charlie = tempfile::tempdir().unwrap();
    assert!(run_in(charlie.path(), &["init"]).status.success());
    let charlie_pk =
        extract_line(&stdout(&run_in(charlie.path(), &["identity"])), "Public Key:").to_string();
    let bad_ip = run_in(
        alice.path(),
        &[
            "peer",
            "add",
            "--public-key",
            &charlie_pk,
            "--ip",
            "8.8.8.8",
        ],
    );
    assert!(!bad_ip.status.success());
    let err = format!("{}{}", stdout(&bad_ip), stderr(&bad_ip));
    assert!(err.contains("10.42.0.0/24") || err.contains("overlay"), "{err}");

    let removed = run_in(alice.path(), &["peer", "remove", "bob"]);
    assert!(removed.status.success(), "stderr: {}", stderr(&removed));
    let empty = run_in(alice.path(), &["peer", "list"]);
    assert!(stdout(&empty).contains("No trusted peers"));
}

#[test]
fn peer_cannot_add_self() {
    let dir = tempfile::tempdir().unwrap();
    assert!(run_in(dir.path(), &["init"]).status.success());
    let pk = extract_line(&stdout(&run_in(dir.path(), &["identity"])), "Public Key:").to_string();
    let add = run_in(
        dir.path(),
        &["peer", "add", "--public-key", &pk, "--ip", "10.42.0.1"],
    );
    assert!(!add.status.success());
    let err = format!("{}{}", stdout(&add), stderr(&add));
    assert!(err.contains("own public key"), "{err}");
}

#[test]
fn export_then_peer_import() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    assert!(run_in(alice.path(), &["init"]).status.success());
    let export = run_in(
        alice.path(),
        &["export", "--ip", "10.42.0.1", "--endpoint", "192.0.2.10:51820"],
    );
    assert!(export.status.success(), "stderr: {}", stderr(&export));
    let body = stdout(&export);
    assert!(body.contains("public_key"));
    assert!(body.contains("10.42.0.1"));
    assert!(!body.to_lowercase().contains("private_key"));

    let rec = alice.path().join("alice.toml");
    fs::write(&rec, &body).unwrap();
    assert!(run_in(bob.path(), &["init"]).status.success());
    let imported = run_in(
        bob.path(),
        &["peer", "import", rec.to_str().unwrap(), "--name", "alice"],
    );
    assert!(imported.status.success(), "stderr: {}", stderr(&imported));
    let listed = stdout(&run_in(bob.path(), &["peer", "list"]));
    assert!(listed.contains("alice"));
    assert!(listed.contains("10.42.0.1"));
    assert!(listed.contains("192.0.2.10:51820"));
}

#[test]
fn status_after_init_hides_secrets() {
    let dir = tempfile::tempdir().unwrap();
    assert!(run_in(dir.path(), &["init"]).status.success());
    let st = run_in(dir.path(), &["status"]);
    assert!(st.status.success(), "stderr: {}", stderr(&st));
    let out = stdout(&st);
    assert!(out.contains("Peer ID:"));
    assert!(out.contains("Public Key:"));
    assert!(out.contains("Overlay:") || out.contains("Coordinator:"));
    assert!(!out.to_lowercase().contains("private"));
    assert!(!out.contains("Join token:"));
}

#[test]
fn join_refuses_unreachable_coordinator() {
    let dir = tempfile::tempdir().unwrap();
    assert!(run_in(dir.path(), &["init"]).status.success());
    let out = run_in(
        dir.path(),
        &[
            "join",
            "--coordinator",
            "127.0.0.1:1",
            "--token",
            "lab-token",
            "--ip",
            "10.42.0.1",
        ],
    );
    assert!(!out.status.success());
    let err = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        err.contains("Connection refused")
            || err.contains("connect")
            || err.contains("os error")
            || err.contains("control-plane"),
        "{err}"
    );
    let local = fs::read_to_string(dir.path().join("local.toml")).unwrap();
    assert!(local.contains("127.0.0.1:1"));
    assert!(local.contains("lab-token"));
}

#[test]
fn help_lists_join_sync_status() {
    let output = Command::new(mynet_bin())
        .arg("--help")
        .output()
        .expect("help");
    assert!(output.status.success());
    let stdout = stdout(&output);
    assert!(stdout.contains("join"));
    assert!(stdout.contains("sync"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("start"));
}

#[test]
fn connect_garbage_secret_fails_before_vpn() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_in(dir.path(), &["connect", "not-an-invite"]);
    assert!(!out.status.success());
    let err = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        err.contains("invite") || err.contains("rnet1"),
        "{err}"
    );
}

#[test]
fn start_help_mentions_other_machine() {
    let output = Command::new(mynet_bin())
        .args(["start", "--help"])
        .output()
        .expect("start help");
    assert!(output.status.success(), "{}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("secret") || stdout.contains("Ctrl-C") || stdout.contains("Start"));
}

#[test]
fn start_without_root_explains_sudo() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_in(dir.path(), &["start"]);
    if out.status.success() {
        return;
    }
    let err = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        err.contains("sudo")
            || err.contains("root")
            || err.contains("CAP_NET")
            || err.contains("not permitted")
            || err.contains("LAN")
            || err.contains("discovery"),
        "{err}"
    );
}

#[test]
fn tun_test_without_cap_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_in(
        dir.path(),
        &["tun-test", "--ip", "10.42.0.1", "--interface", "mynettst0", "--duration", "0"],
    );
    if out.status.success() {
        // Privileged environment created a real TUN; that is also a pass.
        return;
    }
    let err = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        err.contains("CAP_NET_ADMIN")
            || err.contains("Permission")
            || err.contains("/dev/net/tun")
            || err.contains("No such file"),
        "{err}"
    );
}
