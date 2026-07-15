#!/usr/bin/env bash

# Keep direct helper-script invocations on the same generated dependency
# workspace as hosted CI. Explicit callers such as release signoff retain their
# independently supplied GOWORK value.
ci_select_dependency_workspace() {
  local root=$1
  if [[ -z ${GOWORK:-} && -f "$root/.audit/ci.env" ]]; then
    # shellcheck disable=SC1091
    source "$root/.audit/ci.env"
  fi
  if [[ -n ${GOWORK:-} ]]; then
    export GOWORK
  fi
}
