#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wago_dir=$(realpath "${CURRENT_WAGO_DIR:-$root/.wago/wago-current-plugin-lifecycle}")
workers_dir=$(realpath "${WORKERS_DIR:-$root/.wago/workers-plugin}")
net_dir=$(realpath "${CURRENT_NET_DIR:-$root/.wago/net-current-plugin-registration}")
adoption=${CURRENT_PLUGIN_ADOPTION:-review}
require_production=${REQUIRE_PUBLISHED_WAGO_MERGE:-0}

readonly wago_main=7fbc00a57624b26ba8d528d97b419b670e85f64b
readonly wago_review=e44b1baa6eabfba07967a4458fdb56983cb054ae
readonly wago_review_parent=7fbc00a57624b26ba8d528d97b419b670e85f64b
readonly production_merge=97e6f91e6c822491577faa86f3c30aa5a8fff1e8
readonly production_parent1=54499ba5135f69a062e23a7255f4a408d6cecf8c
readonly production_parent2=ffd5ef4b122cbd019897eeea3503789ab5860e4a
readonly net_review=5b444e9dfbbf1b64e7b1f923f1dc3579a4aaf87e
readonly net_review_parent=29d59163a500e96f9567f14beeb4f3bb04e6351e
readonly workers_review=1e9139756d8a3c631c59c00b028038c83bfa8341
readonly workers_parent1=5cb4efff83f0a519311fcf03b63496433f2901f0
readonly workers_parent2=08466d04599d7c0da88d4c5cda73a62c775a8dfc

fail() { echo "current-plugin-topology-audit: $*" >&2; exit 1; }
parents() { git -C "$1" show -s --format=%P "$2"; }
remote_refs() { git -C "$1" ls-remote origin; }
refs_for() { awk -v want="$1" '$1 == want {print $2}'; }

for command in git python3 realpath awk grep paste; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
[[ "$adoption" == review || "$adoption" == adopted ]] || fail "CURRENT_PLUGIN_ADOPTION must be review or adopted"
[[ "$require_production" == 0 || "$require_production" == 1 ]] || fail "REQUIRE_PUBLISHED_WAGO_MERGE must be 0 or 1"
for directory in "$wago_dir" "$workers_dir" "$net_dir"; do
  [[ -d "$directory" ]] || fail "missing repository: $directory"
done

# Refresh moving refs before making any publication or topology decision.
git -C "$wago_dir" fetch --prune origin
git -C "$workers_dir" fetch --prune origin
git -C "$net_dir" fetch --prune origin

[[ $(git -C "$wago_dir" rev-parse refs/remotes/origin/main) == "$wago_main" ]] ||
  fail "Wago origin/main moved; replay and re-review the lifecycle commit before adoption"
[[ $(git -C "$workers_dir" rev-parse refs/remotes/origin/main) == "$workers_review" ]] ||
  fail "workers origin/main moved; re-review external lifecycle composition"
[[ $(git -C "$wago_dir" rev-parse HEAD) == "$wago_review" ]] || fail "current Wago review checkout drifted"
[[ $(git -C "$net_dir" rev-parse HEAD) == "$net_review" ]] || fail "current networking review checkout drifted"
[[ $(git -C "$workers_dir" rev-parse HEAD) == "$workers_review" ]] || fail "workers checkout drifted"
[[ $(parents "$wago_dir" "$wago_review") == "$wago_review_parent" ]] || fail "current Wago review parent drifted"
[[ $(parents "$net_dir" "$net_review") == "$net_review_parent" ]] || fail "current networking review parent drifted"
[[ $(parents "$workers_dir" "$workers_review") == "$workers_parent1 $workers_parent2" ]] || fail "workers ordered parents drifted"
[[ $(parents "$wago_dir" "$production_merge") == "$production_parent1 $production_parent2" ]] || fail "production Wago merge ordered parents drifted"

wago_remote=$(remote_refs "$wago_dir")
workers_remote=$(remote_refs "$workers_dir")
net_remote=$(remote_refs "$net_dir")
wago_review_refs=$(printf '%s\n' "$wago_remote" | refs_for "$wago_review" | paste -sd, -)
production_refs=$(printf '%s\n' "$wago_remote" | refs_for "$production_merge" | paste -sd, -)
workers_refs=$(printf '%s\n' "$workers_remote" | refs_for "$workers_review" | paste -sd, -)
net_review_refs=$(printf '%s\n' "$net_remote" | refs_for "$net_review" | paste -sd, -)
[[ -n "$workers_refs" ]] || fail "exact external workers subject is not fetchable from origin"
if [[ "$adoption" == adopted ]]; then
  [[ -n "$wago_review_refs" ]] || fail "adopted Wago lifecycle subject is not fetchable from origin"
  [[ -n "$net_review_refs" ]] || fail "adopted networking subject is not fetchable from origin"
fi
if [[ "$require_production" == 1 && -z "$production_refs" ]]; then
  fail "production Wago merge must be published without rebasing or squashing"
fi

# Exact current Wago documentation reserves pooling for a future external plugin;
# workers itself contains no pool implementation. A newly named organization
# repository forces review instead of silently changing the unsupported claim.
git -C "$wago_dir" grep -q 'reserved for a future plugin' "$wago_main" -- docs/plugin-api-plan.md ||
  fail "Wago no longer documents pooling as a future plugin"
if git -C "$workers_dir" grep -Eqi '(^|[^[:alpha:]])pool(ing)?([^[:alpha:]]|$)' "$workers_review" -- .; then
  fail "workers now contains pool-related source or documentation; review it separately"
fi
pool_repositories=$(python3 - <<'PY'
import json
import urllib.parse
import urllib.request

url = "https://api.github.com/orgs/wago-org/repos?per_page=100&type=public"
names = []
while url:
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "wago-net-current-plugin-topology-audit",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        names.extend(repository["name"] for repository in json.load(response))
        links = {}
        for item in response.headers.get("Link", "").split(","):
            if ";" not in item:
                continue
            target, relation = item.split(";", 1)
            links[relation.strip()] = target.strip()[1:-1]
        url = links.get('rel="next"', "")
for name in sorted(names, key=str.lower):
    if "pool" in name.lower():
        print(name)
PY
)
[[ -z "$pool_repositories" ]] || fail "pool-named wago-org repositories require review: $pool_repositories"

printf 'Wago origin/main: %s\n' "$wago_main"
printf 'current Wago review refs: %s\n' "${wago_review_refs:-absent}"
printf 'current networking review refs: %s\n' "${net_review_refs:-absent}"
printf 'external workers refs: %s\n' "$workers_refs"
printf 'production Wago merge refs: %s\n' "${production_refs:-absent}"
printf 'adoption mode: %s\n' "$adoption"
printf 'pool implementation: unsupported; exact Wago docs say future plugin, workers has none, no pool-named wago-org repository found\n'
if [[ "$adoption" == review ]]; then
  echo 'publication decision: review evidence only; current Wago/net subjects are not adopted'
else
  echo 'publication decision: exact adopted Wago/net/workers subjects are fetchable'
fi
if [[ -z "$production_refs" ]]; then
  echo 'production decision: exact ordered-parent Wago merge remains unpublished; hosted release automation stays disabled'
else
  echo 'production decision: exact ordered-parent Wago merge is fetchable'
fi

echo 'current-plugin-topology-audit: PASS'
