#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_dir=$(realpath "${CURRENT_REVIEW_SOURCE_DIR:-${SIGNOFF_DIR:-$root/.wago/release-signoff}/source-objects}")
out=$(realpath -m "${CURRENT_REVIEW_OUT:-${SIGNOFF_DIR:-$root/.wago/release-signoff}/current-plugin-review}")
work=$(realpath -m "${CURRENT_REVIEW_WORK_DIR:-$root/.wago/current-plugin-review-work}")

readonly net_revision=5b444e9dfbbf1b64e7b1f923f1dc3579a4aaf87e
readonly net_tree=2ab621daa95f38878ba7cae1893333cf73d759c3
readonly net_parent=29d59163a500e96f9567f14beeb4f3bb04e6351e
readonly wago_revision=e44b1baa6eabfba07967a4458fdb56983cb054ae
readonly wago_tree=826ac3cc506c8ebe1b6631992bf9acb4304ee879
readonly wago_parent=7fbc00a57624b26ba8d528d97b419b670e85f64b
readonly workers_revision=1e9139756d8a3c631c59c00b028038c83bfa8341
readonly workers_tree=ca79d1fb02f19ae15d7b166ffc179c01f9a7c212
readonly workers_parent1=5cb4efff83f0a519311fcf03b63496433f2901f0
readonly workers_parent2=08466d04599d7c0da88d4c5cda73a62c775a8dfc
readonly lneto_revision=ab1a0c735a8b534a1d6322a3e245bc11a09431e7
readonly lneto_tree=8de698038293064eb0fd722760ac64290a639b57
readonly lneto_parent=3c1f0e028100ff9485e87a13a8401b675f13321c

fail() { echo "current-plugin-review-signoff: $*" >&2; exit 1; }
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

for command in git go tinygo cmp realpath sed paste; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
[[ -d "$source_dir" ]] || fail "missing source-object directory: $source_dir"
rm -rf "$out" "$work"
mkdir -p "$out" "$work"

checkout_pack() {
  local name=$1 revision=$2 tree=$3
  shift 3
  local directory=$work/$name pack=$source_dir/$name.pack
  [[ -f "$pack" ]] || fail "missing source-object pack: $pack"
  git init --quiet "$directory"
  git -C "$directory" index-pack --stdin <"$pack" >/dev/null
  git -C "$directory" cat-file -e "$revision^{commit}" 2>/dev/null || fail "$name revision is absent from its pack"
  [[ $(git -C "$directory" rev-parse "$revision^{tree}") == "$tree" ]] || fail "$name tree does not match the bound review tree"
  local actual_parents
  actual_parents=$(git -C "$directory" cat-file -p "$revision" | sed -n 's/^parent //p' | paste -sd ' ' -)
  [[ "$actual_parents" == "$*" ]] || fail "$name ordered parents are '$actual_parents', want '$*'"
  printf '%s\n' "$revision" >"$directory/.git/shallow"
  git -C "$directory" checkout --quiet --detach "$revision"
}

checkout_pack net-current-review "$net_revision" "$net_tree" "$net_parent"
checkout_pack wago-current-review "$wago_revision" "$wago_tree" "$wago_parent"
checkout_pack workers-current "$workers_revision" "$workers_tree" "$workers_parent1" "$workers_parent2"
checkout_pack lneto "$lneto_revision" "$lneto_tree" "$lneto_parent"

mv "$work/net-current-review" "$work/net"
mv "$work/wago-current-review" "$work/wago"
mv "$work/workers-current" "$work/workers"

cat >"$work/go.work" <<EOF
go 1.24.4

use (
	./net
	./wago
	./workers
	./lneto
)
EOF

printf 'net: %s\nWago: %s\nworkers: %s\nlneto: %s\n' \
  "$net_revision" "$wago_revision" "$workers_revision" "$lneto_revision" >"$out/revisions.txt"

(
  cd "$work/net"
  GOWORK="$work/go.work" go test ./... -count=1
) 2>&1 | tee "$out/go-test.txt"
(
  cd "$work/net"
  GOWORK="$work/go.work" go test -race . -run '^TestExternalWorkersPluginRetiresLinkedNetworkingState$' -count=5
) 2>&1 | tee "$out/external-workers-race.txt"
(
  cd "$work/net"
  GOWORK="$work/go.work" go vet ./...
) 2>&1 | tee "$out/go-vet.txt"
(
  cd "$work/workers"
  GOWORK="$work/go.work" go test ./... -count=1
  GOWORK="$work/go.work" go test -race ./... -count=1
  GOWORK="$work/go.work" go vet ./...
) 2>&1 | tee "$out/workers.txt"
(
  cd "$work/net"
  GOWORK="$work/go.work" tinygo test ./...
) 2>&1 | tee "$out/tinygo-test.txt"

WAGO_DIR="$work/wago" LNETO_DIR="$work/lneto" SIGNOFF_CUSTOM_DIR="$out/custom-cli" \
  "$work/net/scripts/custom-cli-signoff.sh" 2>&1 | tee "$out/custom-cli.txt"

cmp "$out/custom-cli/inspection-go.json" "$out/custom-cli/inspection-tinygo.json"
echo 'current-plugin-review-signoff: PASS (immutable current Wago/net/workers workspace; 4 capabilities; 24 imports; linked-child cleanup)'
