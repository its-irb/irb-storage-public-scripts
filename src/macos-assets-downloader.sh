#!/usr/bin/env bash
set -euo pipefail

# download assets
RCLONE_VERSION="1.72.1"
RCLONE_URL="https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-osx-arm64.zip"
FUSET_VERSION="1.0.49"
FUSET_URL="https://github.com/macos-fuse-t/fuse-t/releases/download/${FUSET_VERSION}/fuse-t-macos-installer-${FUSET_VERSION}.pkg"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
curl -L -s "$RCLONE_URL" -o "$WORK_DIR/rclone-v${RCLONE_VERSION}-osx-arm64.zip"
unzip "$WORK_DIR/rclone-v${RCLONE_VERSION}-osx-arm64.zip" -d "$WORK_DIR"
curl -L -s "$FUSET_URL" -o "$WORK_DIR/fuse-t.pkg"
pkgutil --expand "$WORK_DIR/fuse-t.pkg" "$WORK_DIR/extracted"
PAYLOAD=$(find "$WORK_DIR/extracted" -name "Payload" | head -1)
gunzip < "$PAYLOAD" | (cd "$WORK_DIR" && cpio -id --quiet) 2>/dev/null || true

mkdir -p ./assets/bin
ls -lah "$WORK_DIR"
cp "$WORK_DIR/rclone-v${RCLONE_VERSION}-osx-arm64/rclone" ./assets/bin/rclone
cp -R "$WORK_DIR/Library/Frameworks/fuse_t.framework" ./assets/fuse_t.framework