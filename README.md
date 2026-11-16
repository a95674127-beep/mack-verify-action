# MACK Verify — OpenSSH signature verification for CI

Verify files signed with `ssh-keygen -Y sign` (release attestations, signed
manifests, signed release notes) **inside your GitHub Actions pipeline**,
against your own `allowed_signers` file — with the check done by a small,
auditable Rust verifier instead of a shell pipeline.

If the signature is good, the step passes and prints the signer's key
fingerprint. If a single byte of the file changed, the namespace doesn't
match, or the signing key isn't one you authorized, the step fails.

## Usage

Sign a file the usual way (see `ssh-keygen -Y sign`), commit the file, its
`.sig`, and your `allowed_signers`, then:

```yaml
jobs:
  verify-attestation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Verify the signed release attestation
        uses: a95674127-beep/mack-verify-action@v0.1.0
        with:
          file: ATTESTATION.md
          namespace: mack-release
          allowed_signers: allowed_signers
          identity: allenmack
```

Or authorize a single key directly:

```yaml
      - uses: a95674127-beep/mack-verify-action@v0.1.0
        with:
          file: release-notes.md
          namespace: file
          pubkey: 'ssh-ed25519 AAAAC3... you@example'
```

## Inputs

| Input | Required | Notes |
|---|---|---|
| `file` | yes | Path to the signed file. |
| `sig` | no | Path to the `.sig` file. Defaults to `file` + `.sig`. |
| `namespace` | yes | The namespace the signature must be scoped to. |
| `allowed_signers` | one of the two | Path to an OpenSSH `allowed_signers` file. |
| `identity` | with `allowed_signers` | Which identity in the file must have signed. |
| `pubkey` | one of the two | One authorized public key (a line, or a path to a file holding one). |

## A worked example you can check right now

This repository's test fixtures are a real, published attestation: the
owner release attestation for the **MACK** zero-trust stack, signed
2026-11-02. The same three files live in the public
[mack-verification](https://github.com/a95674127-beep/mack-verification)
repository, and the crate's test suite re-verifies them against this
implementation on every run:

```
Good "mack-release" signature for allenmack with ED25519 key SHA256:iKgJ7s1r96fDWGlcPYObuL1cGYJNYL5e1npeF3KSZws
```

Change one digit in the attestation and the verification fails — that is
the entire point.

## How it works

- Parses the OpenSSH `SSHSIG` signature format directly (PROTOCOL.sshsig)
  and verifies the Ed25519 signature over OpenSSH's signed-data
  construction, using [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek).
- Supports the `sha512` and `sha256` hash algorithms `ssh-keygen` uses.
- Checks, in order: the signature's namespace matches the one you require;
  the signing key is authorized for the identity; the signature verifies
  over the file's actual hash.
- Malformed input is an error, never a panic. Ed25519 keys only.

## What it does not do

It verifies signatures. It does not re-run the tests or rebuild the
software an attestation describes — it proves the statement in front of
you is byte-for-byte the statement the key holder signed, and nothing
more. That honest scope is deliberate.

## Use it as a CLI

The Action wraps a small Rust binary:

```bash
cargo build --release
./target/release/mack-verify \
  --file ATTESTATION.md --sig ATTESTATION.md.sig \
  --namespace mack-release \
  --allowed-signers allowed_signers --identity allenmack
```

Exit codes: `0` signature good · `1` verification failed · `2` usage error.

## About

Built by **Allen Mack** of **AI Infinity Force One**, from the same
verification discipline as the MACK zero-trust stack — a Rust platform for
confining and auditing AI-agent workloads, with an owner-signed public
attestation anyone can verify. Licensing:
[AI Infinity Force One on itch.io](https://allenmack.itch.io/ai-infinity-force-one).

## License

MIT — see [LICENSE](LICENSE).
