#!/bin/sh
set -e

REPO="Generalized-Labs/oath"
BIN_DIR="${OATH_INSTALL:-$HOME/.local/bin}"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="x64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "oath: unsupported arch: $ARCH" >&2; exit 1 ;;
esac

case "$OS" in
  darwin) PLATFORM="darwin" ;;
  linux)  PLATFORM="linux" ;;
  *) echo "oath: unsupported OS: $OS (oath supports macOS and Linux)" >&2; exit 1 ;;
esac

BINARY="oath-${PLATFORM}-${ARCH}"
if [ -n "${OATH_VERSION:-}" ]; then
  LATEST=$OATH_VERSION
  case "$LATEST" in
    *[!v0-9.]*|*.*.*.*) echo "oath: OATH_VERSION must be a release tag such as v0.2.5" >&2; exit 1 ;;
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "oath: OATH_VERSION must be a release tag such as v0.2.5" >&2; exit 1 ;;
  esac
else
  if ! LATEST_URL=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest"); then
    echo "oath: could not resolve the latest release of ${REPO}" >&2
    exit 1
  fi
  LATEST=${LATEST_URL##*/}
  if [ -z "$LATEST" ] || [ "$LATEST" = "latest" ]; then
    echo "oath: could not determine the latest release of ${REPO}" >&2
    exit 1
  fi
fi
BASE="https://github.com/${REPO}/releases/download/${LATEST}"
URL="${BASE}/${BINARY}"

echo "Installing oath ${LATEST} for ${PLATFORM}-${ARCH}..."
mkdir -p "$BIN_DIR"
TMP=$(mktemp)
if ! curl -fsSL "$URL" -o "$TMP"; then
  echo "oath: no prebuilt binary for ${PLATFORM}-${ARCH} in ${LATEST} (${URL})." >&2
  echo "      Build from source instead: cargo install --git https://github.com/${REPO} oath-cli" >&2
  rm -f "$TMP"
  exit 1
fi

# Verify checksum. Missing checksum sidecars are release errors, not warnings.
if ! SUM=$(curl -fsSL "${URL}.sha256" 2>/dev/null) || [ -z "$SUM" ]; then
  echo "oath: checksum sidecar missing for ${BINARY} -- refusing to install." >&2
  rm -f "$TMP"
  exit 1
fi
EXPECTED=$(printf '%s' "$SUM" | awk '{print $1}')
if command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "$TMP" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
else
  echo "oath: neither shasum nor sha256sum is available -- refusing to install." >&2
  rm -f "$TMP"
  exit 1
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "oath: checksum mismatch -- refusing to install." >&2
  echo "      expected $EXPECTED" >&2
  echo "      actual   $ACTUAL" >&2
  rm -f "$TMP"
  exit 1
fi
echo "  checksum verified"

mv "$TMP" "$BIN_DIR/oath"
chmod +x "$BIN_DIR/oath"

echo "oath installed to $BIN_DIR/oath"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    echo "Add $BIN_DIR to your PATH if not already there:"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac
