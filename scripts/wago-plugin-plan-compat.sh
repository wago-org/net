#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wago_dir=${WAGO_DIR:-}
if [[ -z "$wago_dir" ]]; then
  wago_dir=$(cd "$root" && go list -m -f '{{.Dir}}' github.com/wago-org/wago)
fi
wago_dir=$(cd "$wago_dir" && pwd)

fail() { echo "wago-plugin-plan-compat: $*" >&2; exit 1; }
require_present() {
  local path=$1 pattern=$2 description=$3
  grep -q -E "$pattern" "$wago_dir/$path" 2>/dev/null ||
    fail "$description is absent ($path / $pattern)"
}

[[ -f "$wago_dir/go.mod" ]] || fail "missing Wago source: $wago_dir"

require_present src/wago/extension.go 'type PluginDefinition struct' 'immutable plugin definition'
require_present src/wago/extension.go 'type PluginProvider struct' 'explicit plugin provider'
require_present src/wago/extension.go 'AuthorityInstanceInstantiateIntercept' 'instantiate interceptor Authority'
require_present src/wago/extension.go 'AuthorityInstanceCloseObserve' 'close observer Authority'
require_present src/wago/extension.go 'AuthorityHostCallerIdentify' 'caller identity Authority'
require_present src/wago/registry.go 'type Registrar struct' 'transactional registrar'
require_present src/wago/access.go 'InstanceInstantiateInterceptor' 'instantiate interceptor access'
require_present src/wago/access.go 'InstanceCloseObserver' 'close observer access'
require_present src/wago/access.go 'CallerResolver' 'caller resolver access'
require_present src/wago/hostcall.go 'type CallerResolver struct' 'expiring exact caller resolver'
require_present plugin/contracts.go 'type Ref\[T any\]' 'typed Contract reference'
require_present plugin/contracts.go 'func Require\[T any\]' 'required typed Contract binding'

grep -q 'AuthorityInstanceInstantiateIntercept' "$root/net.go" ||
  fail 'networking does not request instantiate interception'
grep -q 'AuthorityInstanceCloseObserve' "$root/net.go" ||
  fail 'networking does not request close observation'
grep -q 'AuthorityHostCallerIdentify' "$root/net.go" ||
  fail 'networking does not request caller identity'
grep -q 'AttachIdentity(event.Instance)' "$root/net.go" ||
  fail 'networking does not attach opaque instance identity'
grep -q 'wagoplugin.Require(reg, Contract)' "$root/plugin_lifecycle_test.go" ||
  fail 'typed provider-to-consumer Contract coverage is missing'

if grep -R -E 'RegisterExtension|NewExtension|InstanceHostModule|RequireReinstantiation' \
    --include='*.go' --exclude='*_test.go' "$root" >/dev/null 2>&1; then
  fail 'legacy production plugin API reference remains'
fi

printf 'Wago source: %s\n' "$wago_dir"
echo 'retained: explicit providers, transactional registration, exact Authorities, opaque identity, typed Contracts'
echo 'wago-plugin-plan-compat: vNext compatibility evidence PASS'
