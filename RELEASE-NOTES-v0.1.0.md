# v0.1.0 — first release

**MACK Verify** checks OpenSSH-signed files (`ssh-keygen -Y sign`) in CI:
release attestations, signed manifests, signed release notes — verified
against your `allowed_signers` file or a single authorized key, by a small
auditable Rust verifier (Ed25519, the OpenSSH `SSHSIG` format).

- Fails the step if one byte of the file changed, the namespace doesn't
  match, or the signing key isn't authorized.
- Prints the signer's OpenSSH key fingerprint on success.
- Ships with a real worked example: the test fixtures are a published,
  owner-signed release attestation (MACK stack, 2026-11-02), and this
  repo's CI re-verifies it — including through the Action itself — on
  every push.
- 7 integration tests: the real attestation, a one-byte tamper, wrong
  namespace, wrong identity, unauthorized key, malformed input, and a
  sign/verify round-trip.

Also usable as a plain CLI (`mack-verify`) outside GitHub Actions.
