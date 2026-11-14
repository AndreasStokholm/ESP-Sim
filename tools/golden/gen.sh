#!/bin/sh
# Regenerates test/host/golden_dash.h from the upstream Go DASH simulator.
# Clones jeremybarnum/pod at the commit the C port was made from into
# .cache/upstream-pod (ignored by git), then runs tools/golden against it.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
UP="$ROOT/.cache/upstream-pod"
COMMIT=a491a5ea7171b629490ea5b98381354c72ccc31c

if [ ! -d "$UP/.git" ]; then
    mkdir -p "$ROOT/.cache"
    git clone -q https://github.com/jeremybarnum/pod "$UP"
fi
git -C "$UP" checkout -q "$COMMIT"

cd "$ROOT/tools/golden"
go mod tidy >/dev/null 2>&1 || go mod tidy
go run . > "$ROOT/test/host/golden_dash.h"
echo "wrote test/host/golden_dash.h"
