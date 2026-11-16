//! Verification of OpenSSH signatures — the armored `SSHSIG` format produced by
//! `ssh-keygen -Y sign` and checked by `ssh-keygen -Y verify`.
//!
//! The format is OpenSSH's PROTOCOL.sshsig. This crate parses it directly
//! (SSH wire encoding: big-endian length-prefixed strings) and verifies the
//! Ed25519 signature over the SSHSIG signed-data construction:
//!
//! ```text
//! "SSHSIG" || string(namespace) || string(reserved)
//!          || string(hash_algorithm) || string(hash_of_file)
//! ```
//!
//! (The preamble is the bare 6-byte magic, no NUL — proven against a real
//! `ssh-keygen`-produced signature in the integration tests.)
//!
//! Only Ed25519 keys are supported, matching the keys this tool was built
//! for. Malformed input is always an error, never a panic.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

const MAGIC: &[u8] = b"SSHSIG";
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
const B64_NOPAD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD_NO_PAD;

type VResult<T> = Result<T, String>;

fn err<T>(msg: impl Into<String>) -> VResult<T> {
    Err(msg.into())
}

// ---------------------------------------------------------------------------
// SSH wire-format reader: every read is bounds-checked.
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> VResult<&'a [u8]> {
        if self.buf.len() - self.pos < n {
            return err("unexpected end of data");
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u32(&mut self) -> VResult<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> VResult<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

// ---------------------------------------------------------------------------
// Public key parsing (OpenSSH text form and wire blob form)
// ---------------------------------------------------------------------------

/// Parse an OpenSSH public key blob (`string "ssh-ed25519" || string key`)
/// and return the 32 raw key bytes.
pub fn key_bytes_from_blob(blob: &[u8]) -> VResult<[u8; 32]> {
    let mut r = Reader::new(blob);
    let alg = r.string()?;
    if alg != b"ssh-ed25519" {
        return err("public key is not ssh-ed25519");
    }
    let key = r.string()?;
    if key.len() != 32 {
        return err("ed25519 public key is not 32 bytes");
    }
    if !r.at_end() {
        return err("trailing data in public key blob");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(key);
    Ok(out)
}

/// Parse an OpenSSH public key line (`ssh-ed25519 AAAA... [comment]`)
/// and return the wire blob.
pub fn blob_from_pubkey_line(line: &str) -> VResult<Vec<u8>> {
    let mut parts = line.split_whitespace();
    let kind = parts.next().ok_or("empty public key line")?;
    if kind != "ssh-ed25519" {
        return err("public key line is not ssh-ed25519");
    }
    let b64 = parts.next().ok_or("public key line has no key data")?;
    let blob = B64
        .decode(b64)
        .map_err(|_| "public key is not valid base64")?;
    key_bytes_from_blob(&blob)?; // validate shape
    Ok(blob)
}

/// OpenSSH-style fingerprint of a public key blob: `SHA256:<base64, no padding>`.
pub fn fingerprint(pubkey_blob: &[u8]) -> String {
    let digest = Sha256::digest(pubkey_blob);
    format!("SHA256:{}", B64_NOPAD.encode(digest))
}

/// Parse an `allowed_signers` file into (identity, key blob) pairs.
/// Plain identity lines only: `identity[,identity...] ssh-ed25519 AAAA...`.
pub fn parse_allowed_signers(text: &str) -> VResult<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let identities = parts.next().ok_or("allowed_signers line has no identity")?;
        let kind = parts.next().ok_or("allowed_signers line has no key type")?;
        if kind != "ssh-ed25519" {
            continue; // not a key type we verify; skip quietly
        }
        let b64 = parts.next().ok_or("allowed_signers line has no key data")?;
        let blob = B64
            .decode(b64)
            .map_err(|_| "allowed_signers key is not valid base64")?;
        key_bytes_from_blob(&blob)?;
        for identity in identities.split(',') {
            out.push((identity.to_string(), blob.clone()));
        }
    }
    if out.is_empty() {
        return err("allowed_signers contains no ssh-ed25519 entries");
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// SSHSIG parsing
// ---------------------------------------------------------------------------

pub struct ParsedSignature {
    pub pubkey_blob: Vec<u8>,
    pub key_bytes: [u8; 32],
    pub namespace: String,
    pub reserved: Vec<u8>,
    pub hash_algorithm: String,
    pub signature: [u8; 64],
}

/// Strip the `-----BEGIN/END SSH SIGNATURE-----` armor and decode the blob.
pub fn dearmor(text: &str) -> VResult<Vec<u8>> {
    let mut b64 = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN SSH SIGNATURE-----" {
            inside = true;
            continue;
        }
        if line == "-----END SSH SIGNATURE-----" {
            break;
        }
        if inside {
            if line.contains(':') {
                continue; // armor header line, e.g. "Comment: ..."
            }
            b64.push_str(line);
        }
    }
    if b64.is_empty() {
        return err("no SSH SIGNATURE block found");
    }
    B64.decode(&b64)
        .map_err(|_| "signature block is not valid base64".to_string())
}

pub fn parse_signature(blob: &[u8]) -> VResult<ParsedSignature> {
    let mut r = Reader::new(blob);
    if r.take(6)? != MAGIC {
        return err("not an SSHSIG signature (bad magic)");
    }
    let version = r.u32()?;
    if version != 1 {
        return err(format!("unsupported SSHSIG version {version}"));
    }
    let pubkey_blob = r.string()?.to_vec();
    let key_bytes = key_bytes_from_blob(&pubkey_blob)?;
    let namespace =
        String::from_utf8(r.string()?.to_vec()).map_err(|_| "namespace is not valid UTF-8")?;
    let reserved = r.string()?.to_vec();
    let hash_algorithm =
        String::from_utf8(r.string()?.to_vec()).map_err(|_| "hash algorithm is not valid UTF-8")?;
    // Note: the blob carries no hash field — the file hash is computed by
    // the verifier and enters only through the signed-data construction.
    let sig_blob = r.string()?;
    if !r.at_end() {
        return err("trailing data in signature");
    }
    let mut sr = Reader::new(sig_blob);
    let alg = sr.string()?;
    if alg != b"ssh-ed25519" {
        return err("signature algorithm is not ssh-ed25519");
    }
    let raw_sig = sr.string()?;
    if raw_sig.len() != 64 {
        return err("ed25519 signature is not 64 bytes");
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(raw_sig);
    Ok(ParsedSignature {
        pubkey_blob,
        key_bytes,
        namespace,
        reserved,
        hash_algorithm,
        signature,
    })
}

/// The exact byte string the Ed25519 signature covers (PROTOCOL.sshsig).
pub fn signed_data(namespace: &str, reserved: &[u8], hash_algorithm: &str, hash: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, reserved);
    put_string(&mut out, hash_algorithm.as_bytes());
    put_string(&mut out, hash);
    out
}

fn hash_file(hash_algorithm: &str, data: &[u8]) -> VResult<Vec<u8>> {
    match hash_algorithm {
        "sha512" => Ok(Sha512::digest(data).to_vec()),
        "sha256" => Ok(Sha256::digest(data).to_vec()),
        other => err(format!("unsupported hash algorithm {other}")),
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify `file_bytes` against an armored SSHSIG signature.
///
/// * `expected_namespace` — the namespace the signature must be scoped to.
/// * `identity` — the identity to report / require, if any.
/// * `authorized` — (identity, key blob) pairs the signing key must match;
///   an empty identity in a pair matches any identity (single-key mode).
///
/// On success returns a `ssh-keygen`-style confirmation line.
pub fn verify(
    file_bytes: &[u8],
    signature_text: &str,
    expected_namespace: &str,
    identity: Option<&str>,
    authorized: &[(String, Vec<u8>)],
) -> VResult<String> {
    let blob = dearmor(signature_text)?;
    let sig = parse_signature(&blob)?;

    if sig.namespace != expected_namespace {
        return err(format!(
            "signature namespace is \"{}\", not \"{}\"",
            sig.namespace, expected_namespace
        ));
    }

    // The key that signed must be an authorized key for the identity.
    let mut matched_identity: Option<&str> = None;
    for (id, blob) in authorized {
        if *blob == sig.pubkey_blob
            && (id.is_empty() || identity.is_none() || id == identity.unwrap())
        {
            matched_identity = Some(id.as_str());
            break;
        }
    }
    if matched_identity.is_none() {
        return err("signing key is not an authorized key for this identity");
    }

    let hash = hash_file(&sig.hash_algorithm, file_bytes)?;
    let data = signed_data(&sig.namespace, &sig.reserved, &sig.hash_algorithm, &hash);
    let key = VerifyingKey::from_bytes(&sig.key_bytes)
        .map_err(|_| "signing key is not a valid ed25519 key")?;
    let signature = Signature::from_bytes(&sig.signature);
    key.verify(&data, &signature)
        .map_err(|_| "signature verification failed".to_string())?;

    let who = match identity {
        Some(id) if !id.is_empty() => id,
        _ => match matched_identity {
            Some(id) if !id.is_empty() => id,
            _ => "the authorized key",
        },
    };
    Ok(format!(
        "Good \"{}\" signature for {} with ED25519 key {}",
        sig.namespace,
        who,
        fingerprint(&sig.pubkey_blob)
    ))
}
