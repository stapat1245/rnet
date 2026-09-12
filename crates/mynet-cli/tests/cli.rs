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
    assert!(stdout.contains("version"));
    assert!(stdout.contains("init"));
    assert!(stdout.contains("identity"));
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
