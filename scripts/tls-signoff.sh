#!/usr/bin/env bash
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/lib/ci-dependency-env.sh
source "$root/scripts/lib/ci-dependency-env.sh"
ci_select_dependency_workspace "$root"
cd "$root"

out=$(realpath -m "${TLS_SIGNOFF_DIR:-$root/.wago/tls-signoff}")
manifest=$(realpath -m "${TLS_SIGNOFF_PACKAGE_MANIFEST:-$root/scripts/tls-signoff-packages.tsv}")
module=github.com/wago-org/net

fail() {
  echo "tls-signoff: $*" >&2
  exit 1
}

for command in go python3 realpath; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
[[ -f $manifest ]] || fail "missing package manifest: $manifest"
[[ $out != / && $out != "$root" && $out != "$root/scripts" ]] || fail "unsafe output directory: $out"
[[ ! -d $root/tls/register ]] || fail 'tls/register must not exist'

rm -rf "$out"
mkdir -p "$out/logs"
cp "$manifest" "$out/packages.tsv"

if ! python3 - "$out/packages.tsv" <<'PY'
import sys

path = sys.argv[1]
rows = []
with open(path, encoding="utf-8") as stream:
    for line_number, raw in enumerate(stream, 1):
        line = raw.rstrip("\n")
        fields = line.split("\t")
        if len(fields) != 4 or any(not field for field in fields):
            raise SystemExit(f"tls-signoff: invalid package manifest row {line_number}")
        mode, package, pattern, reason = fields
        if mode not in ("ordinary", "race"):
            raise SystemExit(f"tls-signoff: invalid mode at row {line_number}: {mode}")
        if not package.startswith("github.com/wago-org/net/"):
            raise SystemExit(f"tls-signoff: package outside repository at row {line_number}: {package}")
        rows.append(tuple(fields))
if not rows:
    raise SystemExit("tls-signoff: package manifest is empty")
if rows != sorted(rows):
    raise SystemExit("tls-signoff: package manifest is not sorted")
keys = [(mode, package) for mode, package, _, _ in rows]
if len(keys) != len(set(keys)):
    raise SystemExit("tls-signoff: duplicate mode/package rows")
if not any(mode == "ordinary" and package == "github.com/wago-org/net/tls" for mode, package, _, _ in rows):
    raise SystemExit("tls-signoff: public TLS package lacks ordinary standard-Go coverage")
if not any(mode == "race" for mode, _, _, _ in rows):
    raise SystemExit("tls-signoff: race package set is empty")
PY
then
  exit 1
fi

# Aggregate registration and every self-registering bundle must stay outside the
# TLS implementation. This is checked independently from the Go unit tests.
if go list -deps ./register | grep -Eq "^$module/(tls|internal/(abi|backend|binding|instance|namespace)/tls)$|^$module/internal/backend/gotls$"; then
  fail 'aggregate register depends on TLS'
fi
while IFS=$'\t' read -r key package; do
  [[ $key != net-tls ]] || fail 'net-tls custom-CLI key must not exist'
  if go list -deps "$package" | grep -Eq "^$module/(tls|internal/(abi|backend|binding|instance|namespace)/tls)$|^$module/internal/backend/gotls$"; then
    fail "canonical custom-CLI bundle $key depends on TLS"
  fi
done < <(python3 - "$root/internal/inspectionpolicy/policy.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    policy = json.load(stream)
for bundle in policy.get("bundles", []):
    print(f"{bundle['key']}\t{bundle['package']}")
PY
)

: >"$out/tests.tsv"
rows=0
ordinary_packages=0
race_packages=0
while IFS=$'\t' read -r mode package pattern reason; do
  [[ -n $mode ]] || continue
  rows=$((rows + 1))
  if [[ $mode == ordinary ]]; then
    ordinary_packages=$((ordinary_packages + 1))
  else
    race_packages=$((race_packages + 1))
  fi
  list_log="$out/logs/$mode/${package#"$module/"}/list.log"
  mkdir -p "$(dirname "$list_log")"
  if ! go test "$package" -run '^$' -list "$pattern" >"$list_log" 2>&1; then
    cat "$list_log" >&2
    fail "test discovery failed for $mode $package"
  fi
  matched=0
  while IFS= read -r test_name; do
    [[ $test_name =~ ^Test[A-Za-z0-9_]+$ ]] || continue
    printf '%s\t%s\t%s\n' "$mode" "$package" "$test_name" >>"$out/tests.tsv"
    matched=$((matched + 1))
  done <"$list_log"
  ((matched != 0)) || fail "test pattern matched no tests for $mode $package: $pattern"
done <"$out/packages.tsv"

LC_ALL=C sort -u -o "$out/tests.tsv" "$out/tests.tsv"
test_targets=$(wc -l <"$out/tests.tsv")
((test_targets != 0)) || fail 'resolved TLS test manifest is empty'

failures=0
attempted=0
while IFS=$'\t' read -r mode package pattern reason; do
  [[ -n $mode ]] || continue
  attempted=$((attempted + 1))
  relative=${package#"$module/"}
  log="$out/logs/$mode/$relative/test.log"
  mkdir -p "$(dirname "$log")"
  command=(go test "$package" -count=1 -run "$pattern" -v)
  if [[ $mode == race ]]; then
    command=(go test -race "$package" -count=1 -run "$pattern" -v)
  fi
  printf '\n==> tls-signoff [%d/%d] %s %s %s\n' "$attempted" "$rows" "$mode" "$package" "$pattern"
  if "${command[@]}" >"$log" 2>&1; then
    printf 'tls-signoff: PASS %s %s\n' "$mode" "$package"
  else
    cat "$log" >&2
    printf 'tls-signoff: FAIL %s %s\n' "$mode" "$package" >&2
    failures=$((failures + 1))
  fi
done <"$out/packages.tsv"

cat >"$out/detail.txt" <<EOF
standard_go_tls=tested
aggregate_registration=absent
self_registration=absent
scope=standard-go-client-server-stream-foundation
connection_info_v1=byte-compatible
connection_info_v2=role-aware-additive
listener_authority=explicit
http_https=absent
portable_tinygo_tls=absent
ordinary_packages=$ordinary_packages
race_packages=$race_packages
test_targets=$test_targets
package_runs=$rows
EOF

[[ $attempted == "$rows" ]] || fail "attempted $attempted package runs, expected $rows"
if ((failures != 0)); then
  fail "$failures of $attempted TLS package runs failed"
fi
printf '\ntls-signoff: all %d package runs and %d resolved test targets passed\n' "$attempted" "$test_targets"
