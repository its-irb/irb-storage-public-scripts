#!/usr/bin/env bash
set -euo pipefail

sed -i "" "s|__BUILDPATH__|$(pwd)/..|g" ./pyproject.toml
sed -i "" 's/^version = .*/version = "2.0.0.dev"/' ./pyproject.toml

mkdir -p dist
rm -rf ./build
rm -rf ./dist
cd ..
python -m pip install upgrade pip
python -m pip install uv
python -m uv sync --project bifrost-mount
source bifrost-mount/.venv/bin/activate
cd ./bifrost-mount/src

bash ../../shared/macos-rclone-downloader.sh
bash ../../shared/macos-assets-downloader.sh

echo "__version__ = '2.0.0.dev'" > version.py

cd ..

flet build macos -o ./dist --project bifrost-mount
cp -r ./frameworks/fuse_t.framework ./dist/bifrost-mount.app/Contents/Frameworks/