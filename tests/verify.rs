//! Integration tests. The positive fixture is a real, published artifact:
//! Allen Mack's owner release attestation for the MACK stack, signed
//! 2026-11-02, copied from the public mack-verification repository.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use mack_verify::{parse_allowed_signers, signed_data, verify};
use sha2::{Digest, Sha512};

const ATTESTATION: &[u8] = include_bytes!("fixtures/ATTESTATION.md");
const SIGNATURE: &str = include_str!("fixtures/ATTESTATION.md.sig");
const SIGNERS: &str = include_str!("fixtures/allowed_signers");
const FINGERPRINT: &str = "SHA256:iKgJ7s1r96fDWGlcPYObuL1cGYJNYL5e1npeF3KSZws";

fn signers() -> Vec<(String, Vec<u8>)> {
    parse_allowed_signers(SIGNERS).expect("fixture allowed_signers parses")
}

#[test]
fn real_published_attestation_verifies() {
    let msg = verify(
        ATTESTATION,
        SIGNATURE,
        "mack-release",
        Some("allenmack"),
        &signers(),
    )
    .expect("the real attestation must verify");
    assert!(msg.contains(FINGERPRINT), "message was: {msg}");
}

#[test]
fn tampered_attestation_fails() {
    let mut tampered = ATTESTATION.to_vec();
    tampered[100] ^= 0x01;
    let res = verify(
        &tampered,
        SIGNATURE,
        "mack-release",
        Some("allenmack"),
        &signers(),
    );
    assert!(res.is_err(), "a one-byte change must fail verification");
}

#[test]
fn wrong_namespace_fails() {
    let res = verify(
        ATTESTATION,
        SIGNATURE,
        "file",
        Some("allenmack"),
        &signers(),
    );
    assert!(res.is_err());
}

#[test]
fn wrong_identity_fails() {
    let res = verify(
        ATTESTATION,
        SIGNATURE,
        "mack-release",
        Some("mallory"),
        &signers(),
    );
    assert!(res.is_err());
}

#[test]
fn unauthorized_key_fails() {
    // A signers file naming the same identity but a different key.
    let other = SigningKey::from_bytes(&[9u8; 32]);
    let blob = pubkey_blob(&other);
    let text = format!(
        "allenmack ssh-ed25519 {}",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    );
    let entries = parse_allowed_signers(&text).unwrap();
    let res = verify(
        ATTESTATION,
        SIGNATURE,
        "mack-release",
        Some("allenmack"),
        &entries,
    );
    assert!(res.is_err());
}

#[test]
fn malformed_signatures_error_without_panicking() {
    for bad in [
        "",
        "not a signature at all",
        "-----BEGIN SSH SIGNATURE-----\n!!!\n-----END SSH SIGNATURE-----",
        "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ==\n-----END SSH SIGNATURE-----",
    ] {
        assert!(verify(
            ATTESTATION,
            bad,
            "mack-release",
            Some("allenmack"),
            &signers()
        )
        .is_err());
    }
}

// ---------------------------------------------------------------------------
// Round-trip: sign with our own key in the test, verify with the library.
// ---------------------------------------------------------------------------

fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

fn pubkey_blob(key: &SigningKey) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-ed25519");
    put_string(&mut blob, &key.verifying_key().to_bytes());
    blob
}

fn make_armored_signature(key: &SigningKey, namespace: &str, file: &[u8]) -> String {
    let hash = Sha512::digest(file).to_vec();
    let data = signed_data(namespace, &[], "sha512", &hash);
    let sig = key.sign(&data);

    let mut sig_blob = Vec::new();
    put_string(&mut sig_blob, b"ssh-ed25519");
    put_string(&mut sig_blob, &sig.to_bytes());

    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut blob, &pubkey_blob(key));
    put_string(&mut blob, namespace.as_bytes());
    put_string(&mut blob, &[]);
    put_string(&mut blob, b"sha512");
    put_string(&mut blob, &sig_blob);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    let mut armored = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        armored.push_str(std::str::from_utf8(chunk).unwrap());
        armored.push('\n');
    }
    armored.push_str("-----END SSH SIGNATURE-----\n");
    armored
}

#[test]
fn round_trip_own_signature_verifies_and_binds_namespace() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let file = b"release notes for v1.0.0\n";
    let armored = make_armored_signature(&key, "file", file);
    let authorized = vec![("ci".to_string(), pubkey_blob(&key))];

    let msg = verify(file, &armored, "file", Some("ci"), &authorized)
        .expect("our own signature must verify");
    assert!(msg.contains("Good \"file\" signature for ci"));

    // Same signature, wrong expected namespace: must fail.
    assert!(verify(file, &armored, "mack-release", Some("ci"), &authorized).is_err());
    // Same signature, changed file: must fail.
    assert!(verify(
        b"release notes for v1.0.1\n",
        &armored,
        "file",
        Some("ci"),
        &authorized
    )
    .is_err());
}
