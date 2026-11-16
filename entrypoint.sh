#!/bin/sh
# Maps the Action's inputs (INPUT_* environment variables) to mack-verify flags.
set -eu

SIG="${INPUT_SIG:-}"
if [ -z "$SIG" ]; then
  SIG="${INPUT_FILE}.sig"
fi

set -- --file "$INPUT_FILE" --sig "$SIG" --namespace "$INPUT_NAMESPACE"

if [ -n "${INPUT_ALLOWED_SIGNERS:-}" ]; then
  set -- "$@" --allowed-signers "$INPUT_ALLOWED_SIGNERS"
fi
if [ -n "${INPUT_IDENTITY:-}" ]; then
  set -- "$@" --identity "$INPUT_IDENTITY"
fi
if [ -n "${INPUT_PUBKEY:-}" ]; then
  set -- "$@" --pubkey "$INPUT_PUBKEY"
fi

exec /usr/local/bin/mack-verify "$@"
