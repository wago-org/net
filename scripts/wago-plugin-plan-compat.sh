#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wago_dir=$(realpath "${WAGO_DIR:-$root/.audit/wago}")
require_current=${REQUIRE_CURRENT_PLUGIN_PLAN:-0}

readonly pinned_merge=97e6f91e6c822491577faa86f3c30aa5a8fff1e8
readonly reviewed_redesign=07a70b58ff26d2c8c49b5f879e7733cb375ec13f
readonly observed_main=7794acc82692aac4ff98756a46a017d0d8768087
readonly worker_parent=ffd5ef4b122cbd019897eeea3503789ab5860e4a

fail() { echo "wago-plugin-plan-compat: $*" >&2; exit 1; }
require_present() {
  local revision=$1 path=$2 pattern=$3 description=$4
  git -C "$wago_dir" grep -q -E "$pattern" "$revision" -- "$path" 2>/dev/null ||
    fail "$description is absent at $revision ($path / $pattern)"
}
require_absent() {
  local revision=$1 path=$2 pattern=$3 description=$4
  if git -C "$wago_dir" grep -q -E "$pattern" "$revision" -- "$path" 2>/dev/null; then
    fail "$description is unexpectedly present at $revision ($path / $pattern)"
  fi
}

[[ -d "$wago_dir/.git" ]] || fail "missing Wago repository: $wago_dir"
for revision in "$pinned_merge" "$reviewed_redesign" "$observed_main" "$worker_parent"; do
  git -C "$wago_dir" cat-file -e "$revision^{commit}" 2>/dev/null || fail "missing commit $revision; fetch Wago refs first"
done

git -C "$wago_dir" merge-base --is-ancestor "$worker_parent" "$reviewed_redesign" ||
  fail "reviewed redesign no longer contains the reviewed worker parent"
if git -C "$wago_dir" merge-base --is-ancestor "$pinned_merge" "$reviewed_redesign"; then
  fail "reviewed redesign unexpectedly contains the exact networking merge; re-audit instead of using this decision"
fi

# Contract retained by the redesign.
require_present "$reviewed_redesign" src/wago/hooks.go 'InstantiateManaged' 'managed lifecycle origin'
require_present "$reviewed_redesign" src/wago/hooks.go 'func \(h \*HookRegistry\) BeforeClose' 'instance before-close hooks'
require_present "$reviewed_redesign" src/wago/hooks.go 'func \(h \*HookRegistry\) AfterClose' 'instance after-close hooks'
require_present "$reviewed_redesign" src/wago/managed_instances.go 'type ManagedInstance struct' 'managed instance ownership'
require_present "$reviewed_redesign" src/wago/managed_instances.go 'func \(m \*InstanceManager\) Caller\(caller HostModule\)' 'scoped exact caller resolution'
require_present "$reviewed_redesign" src/wago/plugin_plan.go 'type PluginPlan struct' 'declarative plugin planning'
require_present "$reviewed_redesign" src/wago/access.go 'func \(r \*Registry\) InstanceLifecycle\(\)' 'capability-scoped lifecycle access'
require_present "$reviewed_redesign" src/wago/access.go 'func \(r \*Registry\) HostImports\(\)' 'capability-scoped host import access'

# Networking prerequisites removed or semantically weakened by the redesign.
require_present "$pinned_merge" src/wago/hostcall.go 'type InstanceHostModule interface' 'pinned public exact-instance identity'
require_absent "$reviewed_redesign" src/wago/hostcall.go 'type InstanceHostModule interface' 'public exact-instance identity'
require_present "$reviewed_redesign" src/wago/hostcall.go 'type instanceHostModule struct' 'private scoped caller capability'
require_present "$pinned_merge" src/wago/registry.go 'RequireReinstantiation' 'pinned reset-safety declaration'
require_absent "$reviewed_redesign" src/wago/registry.go 'RequireReinstantiation' 'reset-safety declaration'
require_present "$pinned_merge" src/wago/class.go 'type Class struct' 'pinned class lifecycle'
require_absent "$reviewed_redesign" src/wago/class.go 'type Class struct' 'class lifecycle'
require_present "$pinned_merge" src/wago/workers.go 'type Workers struct' 'pinned worker lifecycle'
require_absent "$reviewed_redesign" src/wago/workers.go 'type Workers struct' 'worker lifecycle'
require_present "$pinned_merge" src/wago/instantiate.go 'func callCloseHook' 'pinned panic-isolated close hook runner'
require_absent "$reviewed_redesign" src/wago/instantiate.go 'func callCloseHook' 'panic-isolated close hook runner'

# Tie the Wago findings to production networking source, not tests alone.
grep -q 'reg.RequireReinstantiation()' "$root/net.go" || fail 'networking no longer declares reset safety; update this audit'
grep -q 'wago.InstanceHostModule' "$root/internal/instance/core/manager.go" || fail 'networking exact-host identity dependency changed; update this audit'

plugin_ref=$(git -C "$wago_dir" rev-parse --verify refs/remotes/origin/plugin-improvements 2>/dev/null || true)
main_ref=$(git -C "$wago_dir" rev-parse --verify refs/remotes/origin/main 2>/dev/null || true)
printf 'pinned networking merge: %s\n' "$pinned_merge"
printf 'reviewed plugin-plan redesign: %s\n' "$reviewed_redesign"
printf 'observed main: %s\n' "$observed_main"
printf 'current origin/plugin-improvements: %s\n' "${plugin_ref:-absent}"
printf 'current origin/main: %s\n' "${main_ref:-absent}"
if [[ "$plugin_ref" != "$reviewed_redesign" || "$main_ref" != "$observed_main" ]]; then
  echo 'remote-tracking refs moved after the reviewed snapshot; fetch and perform a new compatibility audit'
  [[ "$require_current" == 0 ]] || fail 'reviewed compatibility snapshot is not current'
fi
cat <<'EOF'
compatibility decision: MIGRATION REQUIRED; DO NOT MOVE THE NETWORKING PIN
retained: lifecycle hooks, managed origin, scoped caller resolution, managed ownership, plugin planning
missing/changed: public InstanceHostModule, reset eligibility/classes, reviewed workers, panic-isolated close cleanup
EOF

echo 'wago-plugin-plan-compat: reviewed incompatibility evidence PASS'
