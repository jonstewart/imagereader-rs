#!/usr/bin/env bash
#
# Build ewfcompare: e01-rs (as a static library, through its C API) and libewf
# behind one benchmark driver. Needs libewf and The Sleuth Kit installed with
# headers; set PREFIX if they are not under /opt/local (MacPorts).
#
# Usage: e01/compare/build.sh            -> e01/compare/ewfcompare
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(git -C "$here" rev-parse --show-toplevel)"
prefix="${PREFIX:-/opt/local}"
target="${CARGO_TARGET_DIR:-$root/target}"

(cd "$root" && cargo rustc -p e01-rs --release --features capi --lib --crate-type staticlib)

libs=(-L"$prefix/lib" -lewf -ltsk -lz -lpthread)
case "$(uname)" in
  # -w: Apple's linker warns for every object built for a newer macOS than
  # the one being targeted, which says nothing about this program.
  Darwin) libs+=(-lc++ -framework Security -framework CoreFoundation -framework SystemConfiguration -Wl,-w) ;;
  *)      libs+=(-lstdc++ -ldl -lm) ;;
esac

"${CC:-cc}" -O2 -Wall -Wextra -I"$prefix/include" "$here/ewfcompare.c" \
  "$target/release/libe01.a" "${libs[@]}" -o "$here/ewfcompare"

echo "built $here/ewfcompare"
