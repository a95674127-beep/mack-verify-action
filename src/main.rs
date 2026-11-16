//! mack-verify — verify OpenSSH-signed files (`ssh-keygen -Y sign`) in CI.
//!
//! Exit codes: 0 = signature good, 1 = verification failed, 2 = usage error.

use std::process::ExitCode;

use mack_verify::{blob_from_pubkey_line, parse_allowed_signers, verify};

const USAGE: &str = "\
mack-verify — verify an OpenSSH (ssh-keygen -Y) signature

USAGE:
    mack-verify --file <FILE> --sig <FILE.sig> --namespace <NS> \\
                (--allowed-signers <FILE> --identity <NAME> | --pubkey <KEY>)

OPTIONS:
    --file <path>             The signed file.
    --sig <path>              The armored signature file (.sig).
    --namespace <name>        Required signature namespace, e.g. mack-release.
    --allowed-signers <path>  An OpenSSH allowed_signers file.
    --identity <name>         Identity in the allowed_signers file.
    --pubkey <key-or-path>    A single authorized public key: an OpenSSH
                              public key line, or a path to a file holding one.
    -h, --help                Show this help.
";

struct Args {
    file: Option<String>,
    sig: Option<String>,
    namespace: Option<String>,
    identity: Option<String>,
    allowed_signers: Option<String>,
    pubkey: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        file: None,
        sig: None,
        namespace: None,
        identity: None,
        allowed_signers: None,
        pubkey: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let slot = match arg.as_str() {
            "--file" => &mut a.file,
            "--sig" => &mut a.sig,
            "--namespace" => &mut a.namespace,
            "--identity" => &mut a.identity,
            "--allowed-signers" => &mut a.allowed_signers,
            "--pubkey" => &mut a.pubkey,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        };
        *slot = Some(it.next().ok_or(format!("{arg} needs a value"))?);
    }
    Ok(a)
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("mack-verify: FAIL: {msg}");
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        println!("::error::mack-verify: {msg}");
    }
    ExitCode::from(1)
}

fn usage_fail(msg: &str) -> ExitCode {
    eprintln!("mack-verify: {msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => return usage_fail(&e),
    };
    let (Some(file), Some(sig_path), Some(namespace)) = (args.file, args.sig, args.namespace)
    else {
        return usage_fail("--file, --sig and --namespace are all required");
    };

    // Build the authorized-key list from whichever source(s) were given.
    let mut authorized: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(path) = &args.allowed_signers {
        match std::fs::read_to_string(path) {
            Ok(text) => match parse_allowed_signers(&text) {
                Ok(mut entries) => authorized.append(&mut entries),
                Err(e) => return fail(&format!("allowed_signers: {e}")),
            },
            Err(e) => return fail(&format!("cannot read allowed_signers file: {e}")),
        }
    }
    if let Some(pubkey) = &args.pubkey {
        // Accept a path to a key file, or the key line itself.
        let text = match std::fs::read_to_string(pubkey) {
            Ok(t) => t,
            Err(_) => pubkey.clone(),
        };
        let line = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        match blob_from_pubkey_line(line.trim()) {
            Ok(blob) => authorized.push((String::new(), blob)),
            Err(e) => return fail(&format!("public key: {e}")),
        }
    }
    if authorized.is_empty() {
        return usage_fail("give --allowed-signers (with --identity) or --pubkey");
    }

    let file_bytes = match std::fs::read(&file) {
        Ok(b) => b,
        Err(e) => return fail(&format!("cannot read {file}: {e}")),
    };
    let sig_text = match std::fs::read_to_string(&sig_path) {
        Ok(t) => t,
        Err(e) => return fail(&format!("cannot read {sig_path}: {e}")),
    };

    match verify(
        &file_bytes,
        &sig_text,
        &namespace,
        args.identity.as_deref(),
        &authorized,
    ) {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}
