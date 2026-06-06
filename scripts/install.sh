#!/bin/sh
# filament installer — https://filament.autumated.com/install
#
#   curl -fsSL https://filament.autumated.com/install | sh
#
# Detects your platform, downloads the latest release binary from GitHub,
# verifies its SHA-256 against the release's SHA256SUMS, and installs to
# ~/.local/bin (override with FILAMENT_INSTALL_DIR). No sudo, no telemetry,
# fully static binary on Linux. Source: scripts/install.sh in
# https://github.com/Abdk4Moura/filament
set -eu

REPO="Abdk4Moura/filament"
INSTALL_DIR="${FILAMENT_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '\033[1mfilament:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mfilament:\033[0m %s\n' "$*" >&2; exit 1; }

# ----------------------------------------------------------- platform detect
OS=$(uname -s)
ARCH=$(uname -m)
case "$OS" in
  Linux)  case "$ARCH" in
            x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
            *) die "no prebuilt binary for Linux/$ARCH yet — build from source: cargo install filament-cli" ;;
          esac ;;
  Darwin) case "$ARCH" in
            arm64)  TARGET="aarch64-apple-darwin" ;;
            x86_64) TARGET="x86_64-apple-darwin" ;;
            *) die "no prebuilt binary for macOS/$ARCH" ;;
          esac ;;
  MINGW*|MSYS*|CYGWIN*) die "on Windows use:  winget install Abdk4Moura.Filament" ;;
  *) die "unsupported OS: $OS" ;;
esac
ASSET="filament-$TARGET.tar.gz"

# ------------------------------------------------------------------ download
command -v curl >/dev/null || die "curl is required"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# /releases/latest redirects to the newest release; CLI releases are tagged
# cli-vX.Y.Z, so resolve the newest cli-v* tag via the API (no auth needed).
TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=20" \
      | grep -o '"tag_name": *"cli-v[^"]*"' | head -n 1 | cut -d'"' -f4)
[ -n "$TAG" ] || die "could not find a CLI release"
BASE="https://github.com/$REPO/releases/download/$TAG"

say "downloading filament $TAG for $TARGET ..."
curl -fsSL "$BASE/$ASSET" -o "$TMP/$ASSET"
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"

# -------------------------------------------------------------------- verify
if command -v sha256sum >/dev/null; then
  GOT=$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)
elif command -v shasum >/dev/null; then
  GOT=$(shasum -a 256 "$TMP/$ASSET" | cut -d' ' -f1)
else
  die "need sha256sum or shasum to verify the download"
fi
WANT=$(grep "$ASSET" "$TMP/SHA256SUMS" | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || die "checksum mismatch (got $GOT, want $WANT) — aborting"
say "checksum verified"

# ------------------------------------------------------------------- install
mkdir -p "$INSTALL_DIR"
tar -xzf "$TMP/$ASSET" -C "$TMP"
install -m 755 "$TMP/filament" "$INSTALL_DIR/filament"
say "installed $INSTALL_DIR/filament ($("$INSTALL_DIR/filament" --version 2>/dev/null || echo "$TAG"))"

# shell completions (best effort, never fatal)
if [ -n "${BASH_VERSION:-}" ] || [ -f "$HOME/.bashrc" ]; then
  mkdir -p "$HOME/.local/share/bash-completion/completions" 2>/dev/null && \
    "$INSTALL_DIR/filament" completions bash > "$HOME/.local/share/bash-completion/completions/filament" 2>/dev/null || true
fi
if command -v zsh >/dev/null; then
  mkdir -p "$HOME/.zfunc" 2>/dev/null && \
    "$INSTALL_DIR/filament" completions zsh > "$HOME/.zfunc/_filament" 2>/dev/null || true
fi
if [ -d "$HOME/.config/fish" ]; then
  mkdir -p "$HOME/.config/fish/completions" 2>/dev/null && \
    "$INSTALL_DIR/filament" completions fish > "$HOME/.config/fish/completions/filament.fish" 2>/dev/null || true
fi

# PATH hint
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "note: $INSTALL_DIR is not on your PATH — add:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

say ""
say "try it:   filament send <file> --code"
say "          (the other end can be a terminal — or any browser at https://filament.autumated.com)"
