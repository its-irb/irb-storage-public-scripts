#!/usr/bin/env bash
set -euo pipefail

RCLONE_VERSION="1.72.1"
RCLONE_URL="https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-amd64.zip"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

curl -L -s "$RCLONE_URL" -o "$WORK_DIR/rclone.zip"
unzip -j "$WORK_DIR/rclone.zip" "*/rclone" -d "$WORK_DIR/"
chmod +x "$WORK_DIR/rclone"

mkdir -p ./assets/bin
cp "$WORK_DIR/rclone" ./assets/bin/rclone

echo "rclone v${RCLONE_VERSION} descargado en ./assets/bin/rclone"