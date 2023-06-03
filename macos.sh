#!/bin/sh

cd "$(dirname "$0")"

CODESIGN_IDENTITY="${CODESIGN_IDENTITY:-"-"}"

rm -rf ./target/release/bundle/osx/dnject.app target/release/bundle/osx/dnject.dmg
export SDKROOT="/Library/Developer/CommandLineTools/SDKs/MacOSX10.13.sdk"
cargo bundle --release --target x86_64-apple-darwin
pushd ./target/x86_64-apple-darwin/release/bundle/osx/
/usr/local/opt/qt@5/bin/macdeployqt dnject.app -verbose=2 -codesign="${CODESIGN_IDENTITY}" -dmg