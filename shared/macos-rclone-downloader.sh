#!/usr/bin/env bash
set -euo pipefail

RCLONE_VERSION="1.72.1"
RCLONE_URL="https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-osx-arm64.zip"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

curl -L -s "$RCLONE_URL" -o "$WORK_DIR/rclone.zip"
unzip "$WORK_DIR/rclone.zip" -d "$WORK_DIR"

mkdir -p ./assets/bin
cp "$WORK_DIR/rclone-v${RCLONE_VERSION}-osx-arm64/rclone" ./assets/bin/rclone