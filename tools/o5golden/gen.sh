#!/bin/sh
# Regenerates test/host/golden_o5.h from OmnipodKit's Omnipod 5 code.
# Clones loopandlearn/OmnipodKit at a pinned commit into .cache/OmnipodKit
# (ignored by git), copies the files below next to Stubs.swift and main.swift,
# and runs them.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
UP="$ROOT/.cache/OmnipodKit"
COMMIT=8df3d7bea37dead538acba735901cebd29f0f668

if [ ! -d "$UP/.git" ]; then
    mkdir -p "$ROOT/.cache"
    git clone -q https://github.com/loopandlearn/OmnipodKit "$UP"
fi
git -C "$UP" fetch -q --depth 1 origin "$COMMIT" 2>/dev/null || true
git -C "$UP" checkout -q "$COMMIT"

DEST="$ROOT/tools/o5golden/Sources/o5golden/Upstream"
rm -rf "$DEST"
mkdir -p "$DEST"
K="$UP/OmnipodKit"
for f in \
    Bluetooth/Pair/O5KeyExchange.swift \
    Bluetooth/Pair/PairMessage.swift \
    Bluetooth/Util/P256KeyGenerator.swift \
    Bluetooth/Util/X25519KeyGenerator.swift \
    Bluetooth/Util/OmniRandomByteGenerator.swift \
    Bluetooth/Packet/BLEPacket.swift \
    Bluetooth/Packet/PayloadSplitter.swift \
    Bluetooth/Packet/PayloadJoiner.swift \
    Bluetooth/MessagePacket.swift \
    Bluetooth/StringLengthPrefixEncoding.swift \
    Bluetooth/EnDecrypt/EnDecrypt.swift \
    Bluetooth/EnDecrypt/Nonce.swift \
    Bluetooth/O5AidCommands.swift \
    OmnipodCommon/CRC16.swift \
    Common/Data.swift; do
    cp "$K/$f" "$DEST/"
done

cd "$ROOT/tools/o5golden"
swift build -c release -q
"$(swift build -c release --show-bin-path)/o5golden" > "$ROOT/test/host/golden_o5.h"
echo "wrote test/host/golden_o5.h"
