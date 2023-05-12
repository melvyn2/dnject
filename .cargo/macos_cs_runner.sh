#!/bin/sh

# Codesign all produced binaries (e.g. for hardened tests)
codesign --sign - "${1}"

"$@"
