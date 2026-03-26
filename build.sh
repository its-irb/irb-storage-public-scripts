#!/usr/bin/env bash
set -euo pipefail

mkdir -p dist

cd src

bash macos-assets-downloader.sh

echo "__version__ = '2.0.0.dev'" > version.py

cd ..

flet build macos --arch arm64 -o ./dist --project bifrost

cp -R ./src/frameworks/fuse_t.framework ./dist/bifrost.app/Contents/Frameworks/
