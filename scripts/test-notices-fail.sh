#!/usr/bin/env bash
# Proves that the notices check stops on a dependency it must not accept. scripts/notices.sh relies
# on cargo-about for this, so the test uses cargo-about the same way (about.toml, about.hbs, --fail):
#
#   1. a crate with a licence that is not on the allowlist stops the run,
#   2. a crate whose licence cargo-about can not read stops the run with --fail (without --fail it
#      is silently left out and the command succeeds: this is the gap --fail closes),
#   3. a crate under an allowed licence is accepted and its text is in the output.
#
# The test builds tiny crates in a temporary folder; no network is needed. Needs cargo and
# cargo-about in the PATH. Run from anywhere.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_dep() { # name, licence line, optional licence text
  local name="$1" licence="$2" text="${3:-}"
  mkdir -p "$tmp/$name/src"
  printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n%s\n' "$name" "$licence" > "$tmp/$name/Cargo.toml"
  echo "pub fn f() {}" > "$tmp/$name/src/lib.rs"
  if [ -n "$text" ]; then printf '%s\n' "$text" > "$tmp/$name/LICENSE-CUSTOM"; fi
}

make_app() { # dependency name
  mkdir -p "$tmp/app/src"
  printf '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\npublish = false\n\n[dependencies]\n%s = { path = "../%s" }\n' "$1" "$1" > "$tmp/app/Cargo.toml"
  echo "fn main() {}" > "$tmp/app/src/main.rs"
}

# The real allowlist of the repository decides, not a copy of it.
cp "$root/about.toml" "$tmp/about.toml"
cp "$root/about.hbs" "$tmp/about.hbs"
grep -q '^accepted = \[' "$tmp/about.toml" || { echo "ERROR: about.toml has no accepted list." >&2; exit 1; }

generate() { # extra cargo-about arguments
  (cd "$tmp/app" && cargo about generate --config "$tmp/about.toml" "$@" --manifest-path "$tmp/app/Cargo.toml" --output-file "$tmp/out.txt" "$tmp/about.hbs") >/dev/null 2>&1
}

# 1. A licence that is not allowed.
rm -rf "$tmp/app" "$tmp/gpl"; rm -f "$tmp/out.txt"
make_dep gpl 'license = "GPL-3.0-only"'
make_app gpl
if generate --fail; then
  echo "ERROR: a GPL-3.0-only dependency was accepted." >&2
  exit 1
fi
echo "Licence not on the allowlist: stopped, as it must."

# 2. A licence that can not be read.
rm -rf "$tmp/app" "$tmp/gpl"; rm -f "$tmp/out.txt"
make_dep badlic 'license-file = "LICENSE-CUSTOM"' 'Acme Proprietary Licence. All rights reserved. You may not copy, modify or redistribute this software without a written agreement.'
make_app badlic
if ! generate; then
  echo "ERROR: without --fail the command was expected to succeed (it is the case --fail closes)." >&2
  exit 1
fi
if grep -q 'badlic' "$tmp/out.txt"; then
  echo "ERROR: expected badlic to be left out without --fail." >&2
  exit 1
fi
echo "Unreadable licence without --fail: exit 0, crate left out (the gap)."
rm -f "$tmp/out.txt"
if generate --fail; then
  echo "ERROR: --fail did not stop on a crate with an unreadable licence." >&2
  exit 1
fi
echo "Unreadable licence with --fail: stopped, as it must."

# 3. An allowed licence.
rm -rf "$tmp/app" "$tmp/badlic"; rm -f "$tmp/out.txt"
make_dep okdep 'license = "MIT"'
make_app okdep
if ! generate --fail; then
  echo "ERROR: an MIT dependency was refused." >&2
  exit 1
fi
if ! grep -q 'okdep 0.1.0' "$tmp/out.txt"; then
  echo "ERROR: okdep is not in the output." >&2
  exit 1
fi
echo "Allowed licence: accepted and listed."

# scripts/notices.sh must use --fail for every report.
if [ "$(grep -c -- '--fail' "$root/scripts/notices.sh")" -lt 1 ]; then
  echo "ERROR: scripts/notices.sh does not pass --fail to cargo about." >&2
  exit 1
fi
echo "OK"
