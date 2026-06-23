#!/usr/bin/env bash
set -euo pipefail

sed -i "" "s|__BUILDPATH__|$(pwd)/..|g" ./pyproject.toml
sed -i "" 's/^version = .*/version = "2.0.0.dev"/' ./pyproject.toml

mkdir -p dist
rm -rf ./build
rm -rf ./dist
cd ..
python -m pip install --upgrade pip
python -m pip install uv
python -m uv sync --project bifrost-transfer
source bifrost-transfer/.venv/bin/activate
cd ./bifrost-transfer/src

bash ../../shared/macos-rclone-downloader.sh

echo "__version__ = '2.0.0.dev'" > version.py

cd ..

flet build macos -o ./dist --project bifrost-transfer
