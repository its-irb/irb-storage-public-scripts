#!/usr/bin/env bash
set -euo pipefail

RCLONE_VERSION="1.72.1"
RCLONE_URL="https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-amd64.zip"
EMOJI_FONT_URL="https://github.com/googlefonts/noto-emoji/raw/refs/heads/main/fonts/NotoColorEmoji-noflags.ttf"
EMOJI_FONT_NAME="NotoColorEmoji-noflags.ttf"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

curl -L -s "$RCLONE_URL" -o "$WORK_DIR/rclone.zip"
unzip -j "$WORK_DIR/rclone.zip" "*/rclone" -d "$WORK_DIR/"
chmod +x "$WORK_DIR/rclone"

curl -L -s "$EMOJI_FONT_URL" -o "$WORK_DIR/$EMOJI_FONT_NAME"

mkdir -p ./assets/bin
mkdir -p ./assets/fonts
cp "$WORK_DIR/rclone" ./assets/bin/rclone
cp "$WORK_DIR/$EMOJI_FONT_NAME" ./assets/fonts/$EMOJI_FONT_NAME

echo "rclone v${RCLONE_VERSION} descargado en ./assets/bin/rclone"
echo "NotoColorEmoji (noflags) descargado en ./assets/fonts/$EMOJI_FONT_NAME"