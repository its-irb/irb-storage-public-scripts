#!/usr/bin/env bash
set -euo pipefail

RCLONE_VERSION="1.72.1"
RCLONE_URL="https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-osx-amd64.zip"
EMOJI_FONT_URL="https://github.com/googlefonts/noto-emoji/raw/refs/heads/main/fonts/NotoColorEmoji-noflags.ttf"
EMOJI_FONT_NAME="NotoColorEmoji-noflags.ttf"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

curl -L -s "$RCLONE_URL" -o "$WORK_DIR/rclone.zip"
unzip "$WORK_DIR/rclone.zip" -d "$WORK_DIR"

curl -L -s "$EMOJI_FONT_URL" -o "$WORK_DIR/$EMOJI_FONT_NAME"

mkdir -p ./assets/bin
mkdir -p ./assets/fonts
cp "$WORK_DIR/rclone-v${RCLONE_VERSION}-osx-amd64/rclone" ./assets/bin/rclone
cp "$WORK_DIR/$EMOJI_FONT_NAME" ./assets/fonts/$EMOJI_FONT_NAME