#!/usr/bin/env bash
# Makes THIRD-PARTY-NOTICES, the notices of the image (/usr/share/doc/postal-pigeon/THIRD-PARTY-NOTICES),
# or with --check only tests that the file in the repository is up to date.
#
# The file has the licence texts of the Rust crates that are linked into the binary (cargo-about,
# configured in about.toml), and the texts of the Rust standard library and musl libc, which every
# static musl binary contains (legal/). It fails when a crate has a licence that is not on the
# allowlist in about.toml, when cargo-about can not read a licence, and when a licence text is only
# an empty template without a copyright notice.
#
# Needs: cargo-about 0.9.3 (CI installs it with a pinned checksum). Run from anywhere:
#   scripts/notices.sh [--check]
set -euo pipefail

want_version="0.9.3"
cd "$(dirname "$0")/.."

have_version="$(cargo about --version 2>/dev/null | awk '{print $2}' || true)"
if [ "$have_version" != "$want_version" ]; then
  echo "ERROR: cargo-about $want_version is needed, found '${have_version:-none}'." >&2
  echo "Install it: cargo install --locked cargo-about --version $want_version" >&2
  exit 1
fi

mode="write"
if [ "${1:-}" = "--check" ]; then mode="check"; fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# A licence template that was never filled in ("Copyright (c) <year> <copyright holders>") is not a
# copyright notice. cargo-about writes it when a crate has no licence file. Blanks are written in
# angle, square or curly brackets.
placeholder='[<[{](year|fullname|owner|copyright holders?|name of author|organi[sz]ation)[]>}]'

# make_notices <manifest> <output> <product> <image-doc-dir> <binary>
make_notices() {
  local manifest="$1" output="$2" product="$3" docdir="$4" binary="$5"
  local body="$tmp/body.txt" file="$tmp/$(basename "$docdir").txt"

  # --fail stops on a crate whose licence can not be read; without it the crate is left out and the
  # command still succeeds.
  cargo about generate --config about.toml --locked --fail \
    --manifest-path "$manifest" --output-file "$body" about.hbs

  if grep -n -i -E "$placeholder" "$body" >&2; then
    echo "ERROR: $output would contain a licence template without a copyright notice (lines above)." >&2
    echo "Clarify the crate in about.toml so that its real licence file is used." >&2
    exit 1
  fi
  local crates
  crates="$(grep -E '^  [^ ]+ [0-9]' "$body" | sed -e 's/ (.*//' | sort -u | wc -l | tr -d ' ')"
  if [ "$crates" -eq 0 ]; then
    echo "ERROR: no crate in $output." >&2
    exit 1
  fi

  {
    cat <<HEAD
THIRD-PARTY NOTICES

$product is free software under the GNU Affero General Public License, version 3 (see the
file LICENSE). The $binary program contains the third-party software listed below. Each
section gives the licence text and the packages it applies to.

This file is made by scripts/notices.sh from the dependencies of the program. Do not edit it.

The Rust crates are those that $binary is built from, for linux/amd64 and linux/arm64 (static
musl). A crate that only runs while the program is built (a build script) is not listed. The
crate of Postal Pigeon itself is under the same licence as the program and is not repeated here. The container image is based on Alpine Linux; the packages that Alpine
installs keep their own licence information in the image (/lib/apk/db/installed).

==============================================================================
Rust crates ($crates packages)
==============================================================================

HEAD
    tr -d '\r' < "$body"
    cat <<TOOL
==============================================================================
Rust standard library and musl libc
==============================================================================

Every static musl program contains the Rust standard library (MIT OR Apache-2.0; the Apache
licence text is above) and the C library musl. Their notices:

--- Rust standard library (MIT) ---

TOOL
    tr -d '\r' < legal/rust-LICENSE-MIT.txt
    printf '\n\n--- musl libc (MIT, and the other notices of its authors) ---\n\n'
    tr -d '\r' < legal/musl-COPYRIGHT.txt
  } > "$file.raw"
  # One newline at the end of the file.
  printf '%s\n' "$(cat "$file.raw")" > "$file"

  if [ "$mode" = "check" ]; then
    if ! cmp -s "$file" "$output"; then
      echo "ERROR: $output is out of date. Run scripts/notices.sh and commit the result." >&2
      diff -u "$output" "$file" | head -40 >&2 || true
      exit 1
    fi
    echo "$output is up to date ($crates crates)."
  else
    cp "$file" "$output"
    echo "Wrote $output ($crates crates)."
  fi
}

make_notices Cargo.toml THIRD-PARTY-NOTICES "Postal Pigeon" postal-pigeon postal-pigeon
