#!/usr/bin/env bash
# Build a profile-guided-optimised release binary of re-argo.
#
#   tools/pgo.sh [TRAINING_BINARY ...]      (default: /usr/bin/ls /usr/bin/bash)
#
# Output: target/pgo/re-argo  (intermediate profile data in target/pgo-data/)
#
# Needs the rustup `llvm-tools` component (provides a llvm-profdata that matches
# rustc's LLVM):  rustup component add llvm-tools
# The training workload is `analyze` + `decompile-all` on each given binary,
# always with --no-cache so the analysis really runs.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$PWD

SYSROOT=$(rustc --print sysroot)
PROFDATA=$(find "$SYSROOT/lib/rustlib" -type f -name llvm-profdata -path '*/bin/*' 2>/dev/null | head -n1 || true)
if [[ -z "$PROFDATA" ]]; then
    echo "error: llvm-profdata not found in the Rust toolchain ($SYSROOT)." >&2
    echo "Install it with:" >&2
    echo "    rustup component add llvm-tools" >&2
    echo "(or: rustup component add llvm-tools-preview on older toolchains), then re-run tools/pgo.sh." >&2
    exit 1
fi

TRAIN=("$@")
if [[ ${#TRAIN[@]} -eq 0 ]]; then
    TRAIN=(/usr/bin/ls /usr/bin/bash)
fi
for f in "${TRAIN[@]}"; do
    [[ -f "$f" ]] || { echo "error: training binary not found: $f" >&2; exit 1; }
done

TARGET=$(rustc -vV | sed -n 's/^host: //p')
PGO_DATA="$ROOT/target/pgo-data"
GEN_DIR="$ROOT/target/pgo-gen"
OUT_DIR="$ROOT/target/pgo"
rm -rf "$PGO_DATA" "$GEN_DIR"
mkdir -p "$PGO_DATA" "$OUT_DIR"

export CARGO_INCREMENTAL=0

echo "==> [1/4] instrumented build"
RUSTFLAGS="${RUSTFLAGS:-} -Cprofile-generate=$PGO_DATA" \
    cargo build --release --target "$TARGET" --target-dir "$GEN_DIR" -p reargo-cli
GEN_BIN="$GEN_DIR/$TARGET/release/re-argo"

echo "==> [2/4] training run"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
for f in "${TRAIN[@]}"; do
    echo "    $f"
    "$GEN_BIN" --no-cache analyze "$f" >/dev/null 2>&1 || true
    "$GEN_BIN" --no-cache decompile-all "$f" -o "$WORK/decomp" --skip-errors >/dev/null 2>&1 || true
    rm -rf "$WORK/decomp"
done

echo "==> [3/4] merging profiles"
"$PROFDATA" merge -o "$PGO_DATA/merged.profdata" "$PGO_DATA"/*.profraw

echo "==> [4/4] optimised build"
RUSTFLAGS="${RUSTFLAGS:-} -Cprofile-use=$PGO_DATA/merged.profdata" \
    cargo build --release --target "$TARGET" --target-dir "$ROOT/target/pgo-build" -p reargo-cli
cp "$ROOT/target/pgo-build/$TARGET/release/re-argo" "$OUT_DIR/re-argo"
echo "PGO binary: $OUT_DIR/re-argo"
