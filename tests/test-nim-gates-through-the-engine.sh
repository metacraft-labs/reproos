#!/usr/bin/env bash
set -uo pipefail

# Two gates: the registered Nim gates must RUN under `repro build`,
# and a gate whose tool identities are incomplete must still FAIL LOUDLY.
#
#   t_registered_nim_gates_run_through_the_engine
#     Every registered target below is built through `repro build` and must
#     exit 0. All of them are named explicitly: fixing one and leaving the
#     rest is the likely half-landing, and a gate that only runs from a
#     development shell that happens to have `nim` on PATH is, for CI and
#     for a clean checkout, an unregistered gate.
#
#   t_a_gate_missing_a_tool_identity_still_fails_loudly   (NEGATIVE)
#     `nim` is removed from one target's declared identities and the same
#     `repro build` is run again. It must FAIL, and the failure must name
#     the missing tool. It must not pass, and it must not skip. This is the
#     falsifiability gate: the tempting wrong fix here is to make the
#     wrapper skip when its compiler is absent, which would turn four loud
#     failures into four silent passes -- strictly worse than the bug.
#     The mutation is applied to a working copy of repro/workflows.nim and
#     unconditionally restored, including on the failure paths.
#
# This script is deliberately NOT a registered `repro build` target: it
# drives the engine, and registering it would nest `repro build` inside
# `repro build` and would mutate repro/workflows.nim underneath a
# concurrent plan. Call it directly -- from CI, and at review time:
#
#   bash tests/test-nim-gates-through-the-engine.sh
#
# The always-on, registered half of this is structural and lives in
# tests/check_source_composition.py (`repro lint` /
# `repro build test-source-composition`): it re-checks that every Nim gate
# routes through tests/nim-gate.sh, that each one's declared tool
# identities cover what its wrapper actually invokes, that each declared
# name is also in the package's `uses:` block, and that the helper's
# missing-tool path exits non-zero instead of skipping.
#
# Environment. The ambient Nix-installed engine plans this repository
# against a read-only store path and dies before it reaches a target, so
# every invocation here points it at the engine source tree instead:
#
#   REPROBUILD_SOURCE_ROOT=<workspace>/reprobuild REPROBUILD_NO_RUNQUOTA=1 \
#     repro build … --no-runquota
#
# Override REPRO_BIN / REPROBUILD_SOURCE_ROOT to point elsewhere.

script_dir="${BASH_SOURCE[0]%/*}"
repo_root="$(cd "$script_dir/.." && pwd)"
workspace_root="$(cd "$repo_root/.." && pwd)"

REPRO_BIN="${REPRO_BIN:-repro}"
REPROBUILD_SOURCE_ROOT="${REPROBUILD_SOURCE_ROOT:-$workspace_root/reprobuild}"
export REPROBUILD_SOURCE_ROOT
export REPROBUILD_NO_RUNQUOTA=1

WORKFLOWS="$repo_root/repro/workflows.nim"
WORK="$repo_root/build/test-nim-gates-through-the-engine"

# The registered targets whose action compiles and runs a Nim test.
# Keep in step with the wrappers that source tests/nim-gate.sh; the
# structural gate in tests/check_source_composition.py fails if a new one
# appears that is not declared correctly, and this list is what proves the
# declaration actually works.
TARGETS=(
  test-disk-layout-presets
  test-installer-disk-layout-parity
  test-initramfs-verity-tpm
  test-guest-verity-tpm
  test-image-boot-smoke
)

# The target the negative case mutates. `test-disk-layout-presets` is the
# cheapest of the five, and it is the gate the defect was first
# reproduced on.
NEGATIVE_TARGET=test-disk-layout-presets

# Each `repro build` here costs ~12 minutes on a loaded host, so the two
# cases can be run separately while iterating. Full run (both cases) is the
# default and is what review should record.
#
#   --targets a,b     run the positive case for these targets only
#   --skip-negative   omit the negative case
#   --negative-only   omit the positive case
run_positive=1
run_negative=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --targets)       IFS=, read -r -a TARGETS <<< "$2"; shift 2 ;;
    --targets=*)     IFS=, read -r -a TARGETS <<< "${1#*=}"; shift ;;
    --skip-negative) run_negative=0; shift ;;
    --negative-only) run_positive=0; shift ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

failures=0

pass() { echo "[pass] $*"; }
fail() { echo "[fail] $*" >&2; failures=$((failures + 1)); }

run_target() {
  # run_target <target> <logfile> -> exit code of `repro build`
  local target="$1" log="$2"
  ( cd "$repo_root" && "$REPRO_BIN" build "$target" --no-runquota ) \
    >"$log" 2>&1
}

mkdir -p "$WORK"

# ---------------------------------------------------------------------------
# t_registered_nim_gates_run_through_the_engine
# ---------------------------------------------------------------------------

if [[ $run_positive -eq 1 ]]; then
  for target in "${TARGETS[@]}"; do
    log="$WORK/$target.log"
    run_target "$target" "$log"
    code=$?
    if [[ $code -eq 0 ]]; then
      pass "t_registered_nim_gates_run_through_the_engine: repro build $target exited 0"
    else
      fail "t_registered_nim_gates_run_through_the_engine: repro build $target exited $code"
      sed -e 's/^/    | /' "$log" >&2
    fi
  done
fi

# ---------------------------------------------------------------------------
# t_a_gate_missing_a_tool_identity_still_fails_loudly  (NEGATIVE)
# ---------------------------------------------------------------------------

if [[ $run_negative -eq 0 ]]; then
  if [[ $failures -ne 0 ]]; then
    echo "nim gates through the engine: FAIL ($failures)" >&2
    exit 1
  fi
  echo "nim gates through the engine: PASS (positive case only)"
  exit 0
fi

backup="$WORK/workflows.nim.orig"
cp "$WORKFLOWS" "$backup"
restore_workflows() {
  if [[ -f "$backup" ]]; then
    cp "$backup" "$WORKFLOWS"
  fi
}
trap restore_workflows EXIT INT TERM

# Drop `"nim"` from the mutated target's identity list only. The list is
# the one immediately preceding `discard target("<NEGATIVE_TARGET>"`.
python3 - "$WORKFLOWS" "$NEGATIVE_TARGET" <<'PY'
import re
import sys

path, target = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
anchor = text.index('discard target("%s"' % target)
start = text.rindex(".withToolIdentities(", 0, anchor)
end = text.index("])", start) + 2
block = text[start:end]
if '"nim"' not in block:
    sys.exit("the identity list for %s does not declare nim; "
             "nothing to mutate" % target)
mutated = re.sub(r'"nim",\s*', "", block, count=1)
if mutated == block:
    mutated = re.sub(r',\s*"nim"', "", block, count=1)
if mutated == block:
    sys.exit("could not remove nim from %s's identity list" % target)
open(path, "w", encoding="utf-8").write(text[:start] + mutated + text[end:])
PY
if [[ $? -ne 0 ]]; then
  fail "t_a_gate_missing_a_tool_identity_still_fails_loudly: could not apply the mutation"
  restore_workflows
  trap - EXIT INT TERM
  echo "nim gates through the engine: FAIL"
  exit 1
fi

if cmp -s "$WORKFLOWS" "$backup"; then
  fail "t_a_gate_missing_a_tool_identity_still_fails_loudly: the mutation changed nothing"
else
  log="$WORK/negative-$NEGATIVE_TARGET.log"
  run_target "$NEGATIVE_TARGET" "$log"
  code=$?
  # The diagnostic must NAME the missing identity, not merely fail. Either
  # the wrapper's declaration diagnostic ("required tool(s) not on PATH: nim")
  # or the engine's own plan-time "tool-resolution failed: nim …" counts;
  # anything else means the operator is not told what to declare.
  named='(required tool\(s\) not on PATH|tool-resolution failed|not found in PATH).*\bnim\b'
  if [[ $code -eq 0 ]]; then
    fail "t_a_gate_missing_a_tool_identity_still_fails_loudly: repro build $NEGATIVE_TARGET PASSED without declaring nim; the gate is not testing anything"
    sed -e 's/^/    | /' "$log" >&2
  elif ! grep -Eqi "$named" "$log"; then
    fail "t_a_gate_missing_a_tool_identity_still_fails_loudly: repro build $NEGATIVE_TARGET failed (exit $code) but never named the missing tool"
    sed -e 's/^/    | /' "$log" >&2
  elif grep -qi "\[skip\]" "$log"; then
    fail "t_a_gate_missing_a_tool_identity_still_fails_loudly: the missing tool produced a SKIP; a missing tool must be a failure"
    sed -e 's/^/    | /' "$log" >&2
  else
    pass "t_a_gate_missing_a_tool_identity_still_fails_loudly: repro build $NEGATIVE_TARGET exited $code and named the missing tool"
    grep -Ei -m3 "$named" "$log" | sed -e 's/^/    | /'
  fi
fi

restore_workflows
trap - EXIT INT TERM

if ! cmp -s "$WORKFLOWS" "$backup"; then
  fail "the mutation was not restored; repro/workflows.nim differs from $backup"
fi

if [[ $failures -ne 0 ]]; then
  echo "nim gates through the engine: FAIL ($failures)" >&2
  exit 1
fi
echo "nim gates through the engine: PASS"
