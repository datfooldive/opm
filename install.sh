#!/bin/sh
set -eu

repo="datfooldive/opm"
asset="opm-linux-x86_64"
install_dir="${OPM_INSTALL_DIR:-$HOME/.local/bin}"

[ "$(uname -s)" = "Linux" ] || { echo "opm supports Linux only" >&2; exit 1; }
[ "$(uname -m)" = "x86_64" ] || { echo "opm supports x86_64 only" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
base="https://github.com/$repo/releases/latest/download"

curl -fsSL "$base/$asset" -o "$tmp/$asset"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
(cd "$tmp" && sha256sum -c checksums.txt)

mkdir -p "$install_dir"
chmod 755 "$tmp/$asset"
mv "$tmp/$asset" "$install_dir/opm"
printf 'Installed opm to %s/opm\n' "$install_dir"
