#!/usr/bin/env bash
# Post-release follow-up: after the cli-release workflow finishes for a tag,
# regenerate the Homebrew formula and winget manifests with the REAL release
# hashes. Usage:
#
#   packaging/release-followup.sh cli-v0.1.0
#
# Prints the rendered files into packaging/out/ and, if `gh` is authenticated:
#   - pushes the formula to Abdk4Moura/homebrew-tap
#   - prepares (and with --pr, opens) the winget-pkgs PR branch
set -euo pipefail
TAG="${1:?usage: release-followup.sh cli-vX.Y.Z [--pr]}"
OPEN_PR="${2:-}"
VERSION="${TAG#cli-v}"
REPO="Abdk4Moura/filament"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
mkdir -p "$OUT"

echo "fetching SHA256SUMS for $TAG ..."
SUMS=$(curl -fsSL "https://github.com/$REPO/releases/download/$TAG/SHA256SUMS")
sum_for() { echo "$SUMS" | grep "$1" | cut -d' ' -f1; }
SHA_LINUX=$(sum_for x86_64-unknown-linux-musl.tar.gz)
SHA_MAC_ARM=$(sum_for aarch64-apple-darwin.tar.gz)
SHA_MAC_X64=$(sum_for x86_64-apple-darwin.tar.gz)
SHA_WINDOWS=$(sum_for x86_64-pc-windows-msvc.zip)
for v in SHA_LINUX SHA_MAC_ARM SHA_MAC_X64 SHA_WINDOWS; do
  [ -n "${!v}" ] || { echo "missing checksum: $v"; exit 1; }
done

render() { sed -e "s/@VERSION@/$VERSION/g" -e "s/@SHA_LINUX@/$SHA_LINUX/g" \
               -e "s/@SHA_MAC_ARM@/$SHA_MAC_ARM/g" -e "s/@SHA_MAC_X64@/$SHA_MAC_X64/g" \
               -e "s/@SHA_WINDOWS@/$SHA_WINDOWS/g" "$1"; }

# ------------------------------------------------------------------ homebrew
render "$HERE/brew/filament.rb.tmpl" > "$OUT/filament.rb"
echo "rendered $OUT/filament.rb"
if gh auth status >/dev/null 2>&1; then
  TAPDIR=$(mktemp -d)
  if gh repo clone Abdk4Moura/homebrew-tap "$TAPDIR" -- -q 2>/dev/null; then
    mkdir -p "$TAPDIR/Formula"
    cp "$OUT/filament.rb" "$TAPDIR/Formula/filament.rb"
    git -C "$TAPDIR" add Formula/filament.rb
    if ! git -C "$TAPDIR" diff --cached --quiet; then
      git -C "$TAPDIR" commit -q -m "filament $VERSION"
      git -C "$TAPDIR" push -q
      echo "homebrew-tap updated -> brew install abdk4moura/tap/filament"
    else
      echo "homebrew-tap already current"
    fi
  else
    echo "NOTE: Abdk4Moura/homebrew-tap not found — create it: gh repo create Abdk4Moura/homebrew-tap --public"
  fi
  rm -rf "$TAPDIR"
fi

# -------------------------------------------------------------------- winget
WD="$OUT/winget/manifests/a/Abdk4Moura/Filament/$VERSION"
mkdir -p "$WD"
render "$HERE/winget/Abdk4Moura.Filament.yaml.tmpl" > "$WD/Abdk4Moura.Filament.yaml"
render "$HERE/winget/Abdk4Moura.Filament.installer.yaml.tmpl" > "$WD/Abdk4Moura.Filament.installer.yaml"
render "$HERE/winget/Abdk4Moura.Filament.locale.en-US.yaml.tmpl" > "$WD/Abdk4Moura.Filament.locale.en-US.yaml"
echo "rendered winget manifests under $WD"

if [ "$OPEN_PR" = "--pr" ] && gh auth status >/dev/null 2>&1; then
  WPDIR=$(mktemp -d)
  echo "forking + cloning microsoft/winget-pkgs (shallow) ..."
  gh repo fork microsoft/winget-pkgs --clone=false >/dev/null 2>&1 || true
  ME=$(gh api user --jq .login)
  git clone -q --depth 1 "https://github.com/$ME/winget-pkgs" "$WPDIR"
  BR="filament-$VERSION"
  git -C "$WPDIR" checkout -q -b "$BR"
  DEST="$WPDIR/manifests/a/Abdk4Moura/Filament/$VERSION"
  mkdir -p "$DEST"
  cp "$WD"/*.yaml "$DEST/"
  git -C "$WPDIR" add manifests
  git -C "$WPDIR" commit -q -m "New package: Abdk4Moura.Filament version $VERSION"
  git -C "$WPDIR" push -q -u origin "$BR"
  gh pr create --repo microsoft/winget-pkgs --head "$ME:$BR" \
    --title "New package: Abdk4Moura.Filament version $VERSION" \
    --body "Adds Abdk4Moura.Filament $VERSION (portable zip, x64). P2P file transfer CLI; binaries built and attested by GitHub Actions in https://github.com/$REPO. Validated against manifest schema 1.6.0."
  rm -rf "$WPDIR"
fi
echo "done."
