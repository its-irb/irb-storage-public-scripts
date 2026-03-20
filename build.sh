#!/usr/bin/env bash
set -euo pipefail

mkdir -p dist
cd minio

bash macos-third-party-assets-downloader.sh

echo "__version__ = 'v1.0.92'" > version.py

flet pack bifrost.py \
--distpath ../dist \
--add-binary "assets/bin/rclone:." \
--add-data "assets/fuse_t.framework:fuse_t.framework"
