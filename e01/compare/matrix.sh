#!/usr/bin/env bash
#
# Run every ewfcompare workload against both backends for each image given,
# interleaving the backends so neither consistently runs on a warmer page cache.
# The `sum=` columns of a workload must agree between backends.
#
# Usage: e01/compare/matrix.sh IMAGE.E01 [IMAGE.E01...]
#   WORKLOADS="open seq1m ..."  run a subset (names below)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
bin="$here/ewfcompare"

declare -A W=(
  [open]="open 30"
  [seq4k]="seq 4 4096"
  [seq64k]="seq 64"
  [seq1m]="seq 1024"
  [rand4k]="rand 4 100000"
  [rand64k]="rand 64 20000"
  [rand1m]="rand 1024 2000"
  [rand4k-local]="rand 4 200000 256 4096"
  [rand4k-unaligned]="rand 4 100000 0 1"
  [mt8-rand4k]="mt 8 4 400000"
  [mt8-rand64k]="mt 8 64 80000"
  [tsk-walk]="tsk-walk"
  [tsk-read]="tsk-read"
)
ORDER=(open seq4k seq64k seq1m rand4k rand64k rand1m rand4k-local rand4k-unaligned mt8-rand4k mt8-rand64k tsk-walk tsk-read)
read -r -a wanted <<<"${WORKLOADS:-${ORDER[*]}}"

for img in "$@"; do
  echo "### $img"
  for w in "${wanted[@]}"; do
    # shellcheck disable=SC2086
    for be in libewf e01rs; do
      "$bin" "$be" "$img" ${W[$w]}
    done
  done
done
