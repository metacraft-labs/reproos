# shellcheck shell=bash
#
# The one place ReproOS's Nim-based gates are wired to the build engine.
#
# Every `tests/test-*.sh` wrapper that compiles and runs a Nim test sources
# this file and calls `nim_gate_run`. There is deliberately no second copy of
# the preamble: the wrappers used to hand-roll it, every copy assumed an
# ambient development shell, and all of them died under `repro build` --
# because a registered build action's PATH carries EXACTLY the tool
# identities the action declares, and nothing else, not even coreutils.
#
# Two rules this file exists to enforce, and which the registered
# `test-source-composition` gate re-checks structurally:
#
#   1. A missing tool is a DECLARATION bug. The diagnostic names the tool,
#      the target, and the two places the declaration lives
#      (`withToolIdentities([...])` on the action and the `uses:` block of
#      `package reproosWorkflows`), because under `repro build` the operator
#      cannot fix it by entering a shell.
#
#   2. A missing tool is NEVER a skip. Every check here exits 2. Turning one
#      into a skip would convert a loud failure into a silent pass, which is
#      strictly worse than the bug this file fixes; the negative gate
#      `t_a_gate_missing_a_tool_identity_still_fails_loudly` in
#      tests/test-nim-gates-through-the-engine.sh exists to catch exactly
#      that regression.
#
# `dirname` is not used to find the repo root. Bash parameter expansion is a
# builtin and therefore cannot be a missing tool, so the FIRST diagnostic an
# operator sees is the accurate one instead of `dirname: command not found`.

nim_gate_repo_root() {
  ( cd "${BASH_SOURCE[1]%/*}/.." && pwd )
}

nim_gate_declaration_failure() {
  # nim_gate_declaration_failure <gate-name> <what is missing>
  local gate="$1" what="$2"
  {
    echo "$gate: $what"
    echo
    echo "This is a DECLARATION bug, not a missing development shell."
    echo "A registered build action's PATH carries exactly the tool"
    echo "identities the action declares. Declare what is missing in BOTH"
    echo "places in repro/workflows.nim:"
    echo "  * the .withToolIdentities([...]) list on the action that runs"
    echo "    $gate, and"
    echo "  * the uses: block of 'package reproosWorkflows'."
    echo
    echo "Running this script directly instead? Then use a shell that"
    echo "provides the tools above."
    echo
    echo "This gate does not skip when a tool is absent: a gate that"
    echo "reports success without testing anything is worse than one that"
    echo "fails."
  } >&2
  exit 2
}

nim_gate_require() {
  # nim_gate_require <gate-name> <tool> [<tool> ...]
  local gate="$1"
  shift
  local missing=()
  local tool
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi
  nim_gate_declaration_failure "$gate" \
    "required tool(s) not on PATH: ${missing[*]}"
}

nim_gate_require_any() {
  # nim_gate_require_any <gate-name> <label> <tool> [<tool> ...]
  #
  # For a capability more than one command can supply -- a C++ compiler is
  # `c++` under both the gcc and the clang wrappers. Still a hard failure
  # when none of them is present.
  local gate="$1" label="$2"
  shift 2
  local tool
  for tool in "$@"; do
    if command -v "$tool" >/dev/null 2>&1; then
      return 0
    fi
  done
  nim_gate_declaration_failure "$gate" \
    "$label: none of [$*] is on PATH"
}

nim_gate_c_compiler() {
  # Echo the absolute path of a C compiler taken from the PATH the action
  # was given. `nim c` compiles Nim to C and shells out to one, so a Nim
  # gate needs a compiler identity as surely as it needs `nim`.
  local gate="$1" candidate
  for candidate in cc clang gcc; do
    if command -v "$candidate" >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done
  nim_gate_declaration_failure "$gate" \
    "no C compiler on PATH (looked for cc, clang, gcc); nim compiles to C and shells out to one"
}

nim_gate_run() {
  # nim_gate_run <gate-name> <nim source, relative to the repo root>
  #              [tool identities the gate needs ...]
  #
  # `nim`, `mkdir` and a C compiler are implicit: this helper invokes all
  # three for every gate. Anything the compiled Nim test shells out to
  # (python3, git, bash, ...) is passed by the caller so that the wrapper
  # reads as the gate's full tool contract.
  local gate="$1" nim_rel="$2"
  shift 2
  local repo_root
  repo_root="$( cd "${BASH_SOURCE[1]%/*}/.." && pwd )"
  nim_gate_require "$gate" nim mkdir "$@"

  local cc backend version
  cc="$(nim_gate_c_compiler "$gate")" || exit 2
  # Nim's per-backend flag sets differ (`-fmax-errors=` vs `-ferror-limit=`),
  # so the backend has to match the binary. Matched with bash's own pattern
  # operator rather than `grep`, because `grep` is a tool identity too and
  # this gate must not acquire an undeclared dependency in order to decide
  # what it depends on.
  version="$("$cc" --version 2>/dev/null || true)"
  case "$version" in
    *clang*|*Clang*) backend=clang ;;
    *)               backend=gcc ;;
  esac

  # Pin the C compiler explicitly rather than inheriting `$CC`.
  #
  # Measured, and the reason this block exists: `repro build` replaces only
  # PATH in a build action and inherits every other variable, so a
  # developer shell's `CC=gcc` reached the action; nixpkgs' nim.cfg
  # substitutes it (`gcc.exe %= "$CC"`); and nim then shelled out to a BARE
  # `gcc` that the action's hermetic PATH does not carry -- 31 lines of
  # "gcc: command not found" and exit 1, with `nim` itself correctly
  # declared and resolved. The compiler a gate compiles with must come from
  # its DECLARED identities, never from the caller's environment.
  #
  # REPROOS_NIM_CC_ARGS carries the same decision to any `nim c` the
  # compiled test itself runs (tests/test_installer_disk_layout_parity.nim
  # compiles the rendered hardware.nim files), so there is one answer per
  # gate rather than one per call site.
  REPROOS_NIM_CC_ARGS="--cc:$backend --$backend.exe:$cc --$backend.linkerexe:$cc"
  export REPROOS_NIM_CC_ARGS
  export CC="$cc"

  local checker="$repo_root/build/$gate/check-$gate"
  mkdir -p "$repo_root/build/$gate"
  # shellcheck disable=SC2086 # the flags are constructed above, deliberately word-split
  nim c --hints:off --warnings:off $REPROOS_NIM_CC_ARGS \
    --out:"$checker" "$repo_root/$nim_rel"
  "$checker"
}
