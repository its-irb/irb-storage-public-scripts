#!/usr/bin/env bash
set -euo pipefail

sed -i "" "s|__BUILDPATH__|$(pwd)/..|g" ./pyproject.toml

mkdir -p dist
rm -rf ./build
rm -rf ./dist
cd ..
python -m pip install -r ./shared/requirements.txt
cd ./bifrost-mount/src

bash ../../shared/macos-rclone-downloader.sh
bash ../../shared/macos-assets-downloader.sh

echo "__version__ = '2.0.0.dev'" > version.py

cd ..

flet build macos -o ./dist --project bifrost-mount
cp -r ./src/frameworks/fuse_t.framework ./dist/bifrost-mount.app/Contents/Frameworks/