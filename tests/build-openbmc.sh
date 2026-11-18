#!/bin/bash
# Build the OpenBMC (canopy-qemu, AST2600) image used by test_takeoverd.py.
set -e

TESTS=$(cd "$(dirname "$0")" && pwd)
mkdir -p "${BUILD_DIR:=$TESTS/build}"
BUILD_DIR=$(realpath "$BUILD_DIR")

git -C "$TESTS/.." submodule update --init tests/openbmc
git -C "$TESTS/openbmc" submodule update --init --depth 1 openbmc

[ -f "$BUILD_DIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -f "$BUILD_DIR/id_ed25519"

cd "$TESTS/openbmc"
. ./setup canopy-qemu "$BUILD_DIR/openbmc" > /dev/null

grep -q meta-lacp-test conf/bblayers.conf ||
	echo "BBLAYERS += \"$TESTS/meta-lacp-test\"" >> conf/bblayers.conf
cat > conf/auto.conf <<EOC
CANOPY_CONFIG = "dev"
CANOPY_VERSION = "lacp-test"
IMAGE_INSTALL:append = " lacp-takeoverd lacp-test-config"
LACP_TEST_PUBKEY = "$(cat "$BUILD_DIR/id_ed25519.pub")"
EOC

bitbake obmc-phosphor-image
