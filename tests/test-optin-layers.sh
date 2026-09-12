#!/usr/bin/env bash
#
# Gate: an opt-in layer the build cannot run is loud, and no opt-in
# variable is consumed without its action declaring it.
#
#   t_optin_variable_is_in_the_cache_key       (structural, ~1s)
#   t_unreachable_layer_is_not_a_silent_skip   (behavioural, ~1 min --
#                                               it compiles and runs a
#                                               real shipped gate)
#
# This wrapper is a tool contract and nothing else; see tests/nim-gate.sh.
set -euo pipefail

# shellcheck source=tests/nim-gate.sh
source "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run "optin-layers" "tests/test_optin_layers.nim"
