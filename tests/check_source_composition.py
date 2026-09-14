#!/usr/bin/env python3
"""Validate the source-only composition of the ReproOS build graph."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROOT_RECIPE = ROOT / "repro.nim"
INSTALLER_RECIPE = ROOT / "apps/reproos-installer/package.nim"
ISO_RECIPE = ROOT / "recipes/reproos-iso/package.nim"
IMAGE_RECIPE = ROOT / "recipes/reproos-image/package.nim"
CONTAINER_RECIPE = ROOT / "recipes/reproos-container/package.nim"
WORKFLOW_RECIPE = ROOT / "repro/workflows.nim"
PACKAGE_SETS = ROOT / "repro/package_sets.nim"
STAGE_ROOTFS_SCRIPT = ROOT / "recipes/reproos-iso/scripts/stage-de-rootfs.sh"
BUILD_ISO_SCRIPT = ROOT / "recipes/reproos-iso/scripts/build-iso.sh"
NORMALIZE_RUNTIME_SCRIPT = (
    ROOT / "recipes/reproos-iso/scripts/normalize-source-runtime.sh"
)
CONTRIBUTOR_GUIDE = ROOT / "AGENTS.md"
README = ROOT / "README.md"
CONTAINER_GUIDE = ROOT / "recipes/reproos-container/README.md"
INSTALLED_SSH_TEST = ROOT / "tests/test-installed-ssh.sh"
INCUS_LIFECYCLE_TEST = ROOT / "tests/test-incus-lifecycle.sh"


def source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def require_contains(path: Path, values: list[str], subject: str) -> None:
    content = source(path)
    for value in values:
        if value not in content:
            raise AssertionError(f"{subject} is missing: {value}")


def build_dependencies(path: Path) -> list[str]:
    match = re.search(
        r"^  buildDeps:\r?\n(?P<body>.*?)(?=^  [A-Za-z][A-Za-z0-9]*:)",
        source(path),
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"buildDeps block missing in {path}")
    return re.findall(r'"([^"]+)"', match.group("body"))


def uses_dependencies(path: Path) -> list[str]:
    match = re.search(
        r"^  uses:\r?\n(?P<body>.*?)(?=^  [A-Za-z][A-Za-z0-9]*:)",
        source(path),
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"uses block missing in {path}")
    return re.findall(r'"([^"]+)"', match.group("body"))


def canonical_rootfs_packages() -> list[str]:
    match = re.search(
        r"ReproosGraphicalRootfsPackages\*\s*=\s*@\[(?P<body>.*?)^\]",
        source(PACKAGE_SETS),
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError("canonical graphical rootfs package set is missing")
    return re.findall(r'"([^"]+)"', match.group("body"))


def require_unique(values: list[str], subject: str) -> None:
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        raise AssertionError(f"{subject} contains duplicates: {', '.join(duplicates)}")


def require_registered_action_tools(
    path: Path, binding: str, expected: set[str]
) -> None:
    match = re.search(
        rf"appendRegisteredActionToolIdentityRefs\({re.escape(binding)}\.id,\s*"
        r"@\[(?P<body>.*?)\]\)",
        source(path),
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"tool identities missing for {binding} in {path}")
    actual = set(re.findall(r'"([^"]+)"', match.group("body")))
    missing = sorted(expected - actual)
    if missing:
        raise AssertionError(
            f"{binding} in {path} omits initramfs tools: {', '.join(missing)}"
        )


def shell_call_blocks(path: Path) -> list[tuple[str, str]]:
    """Return (binding, call text) pairs for balanced ``shell(...)`` calls."""
    content = source(path)
    calls: list[tuple[str, str]] = []
    for match in re.finditer(r"\blet\s+(\w+)\s*=\s*shell\(", content):
        depth = 1
        quote = ""
        escaped = False
        cursor = match.end()
        while cursor < len(content) and depth > 0:
            char = content[cursor]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
            elif char in {'"', "'"}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            cursor += 1
        if depth != 0:
            raise AssertionError(f"unbalanced shell call for {match.group(1)} in {path}")
        calls.append((match.group(1), content[match.start():cursor]))
    return calls


def require_shell_action_contracts(path: Path) -> None:
    content = source(path)
    for binding, call in shell_call_blocks(path):
        if "actionId =" not in call:
            raise AssertionError(f"shell action {binding} in {path} has no stable actionId")
        if "extraOutputs =" not in call and "cacheable = false" not in call:
            raise AssertionError(
                f"shell action {binding} in {path} has neither outputs nor cache disabled"
            )
        has_fluent_identities = re.search(
            rf"\blet\s+{re.escape(binding)}\s*=\s*shell\(.*?\)"
            r"\.withToolIdentities\(",
            content,
            flags=re.DOTALL,
        )
        has_explicit_identities = (
            f"appendRegisteredActionToolIdentityRefs({binding}.id" in content
        )
        if not has_fluent_identities and not has_explicit_identities:
            raise AssertionError(
                f"shell action {binding} in {path} has no executable identities"
            )


NIM_GATE_HELPER = ROOT / "tests/nim-gate.sh"

# A command name a Nim gate invokes, mapped to the tool identities that can
# supply it. `c++` is deliberately many-to-one: both the gcc wrapper and the
# clang wrapper ship it, and this repo declares `clang` because the sibling
# reprobuild-packages carries a from-source `gcc` recipe: under from-source
# provisioning a completed source mirror outranks the pinned nixpkgs build,
# and that mirror is what an always-on gate would then compile with.
COMMAND_IDENTITIES = {
    "c++": {"clang", "gcc"},
    "clang++": {"clang"},
    "g++": {"gcc"},
}


def sources_nim_gate_helper(text: str) -> bool:
    return re.search(r'(?m)^\s*\.\s+\S*nim-gate\.sh', text) is not None


def nim_gate_wrappers() -> list[Path]:
    """Every wrapper that compiles a Nim test, however it gets its compiler."""
    return sorted(
        path
        for path in (ROOT / "tests").glob("test-*.sh")
        if "nim c " in source(path) or sources_nim_gate_helper(source(path))
    )


def action_call_for_command(content: str, needle: str) -> tuple[str, str]:
    """Return (binding, call text) of the shell action whose command runs ``needle``."""
    for binding, call in shell_call_blocks(WORKFLOW_RECIPE):
        if needle in call:
            return binding, call
    raise AssertionError(
        f"no registered shell action runs {needle}; a Nim gate that is not "
        "registered cannot run under `repro build`"
    )


def declared_identities(content: str, binding: str) -> set[str]:
    match = re.search(
        rf"\blet\s+{re.escape(binding)}\s*=\s*shell\(.*?\)"
        r"\.withToolIdentities\(\[(?P<body>.*?)\]\)",
        content,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"{binding} declares no tool identities")
    return set(re.findall(r'"([^"]+)"', match.group("body")))


def required_identities(wrapper: Path) -> set[str]:
    """The tool identities a wrapper's own tool contract says it needs."""
    text = source(wrapper)
    required: set[str] = set()
    run = re.search(
        r"^nim_gate_run\s+(?P<body>(?:[^\n]*\\\n)*[^\n]*)$",
        text,
        flags=re.MULTILINE,
    )
    if run is None:
        raise AssertionError(f"{wrapper} sources nim-gate.sh but never calls nim_gate_run")
    words = run.group("body").replace("\\\n", " ").split()
    # <gate-name> <nim source> [tool identities ...]. `nim`, `mkdir` and a C
    # compiler are implicit in the helper and therefore required of every Nim
    # gate: `nim c` lowers Nim to C and shells out to a compiler, so a gate
    # that declares `nim` and nothing else still dies -- measured, with 31
    # lines of "gcc: command not found".
    required.update({"nim", "mkdir", "clang|gcc"})
    required.update(words[2:])
    for any_of in re.finditer(
        r"^nim_gate_require_any\s+(?P<body>(?:[^\n]*\\\n)*[^\n]*)$",
        text,
        flags=re.MULTILINE,
    ):
        # <gate-name> "<label>" <command> ...; the label is quoted and may
        # contain spaces, so take everything after the closing quote.
        tail = any_of.group("body").replace("\\\n", " ")
        if '"' not in tail:
            raise AssertionError(
                f"{wrapper}: nim_gate_require_any needs a quoted label naming "
                "the capability and the tool identity that supplies it"
            )
        commands = tail[tail.rindex('"') + 1:].split()
        alternatives: set[str] = set()
        for command in commands:
            alternatives |= COMMAND_IDENTITIES.get(command, {command})
        if alternatives:
            required.add("|".join(sorted(alternatives)))
    return required


def require_registered_wrappers_do_something() -> None:
    """A registered `bash tests/*.sh` action must run something.

    THE CHECK THAT WAS MISSING, and it was missing in the direction that
    matters. `nim_gate_wrappers()` below selects wrappers by their CONTENT
    -- they compile Nim, or they source the helper -- so a wrapper that does
    NEITHER is not merely unchecked, it is invisible: every rule about tool
    contracts and declared identities is written about a set it is not in.

    A wrapper reduced to comments is therefore a registered gate that exits
    0 having executed nothing, and it passes every other check in this file.
    That is not hypothetical; it was introduced here by an over-broad
    comment deletion and survived a full run of this script. The failure
    mode is a green result that describes no work, which is the one failure
    mode a test suite must not have, so it gets a check of its own rather
    than a note.

    Deliberately crude, and that is the point: it asks only whether any
    line survives the strip of comments, blank lines and shell settings.
    Anything cleverer would be a shell parser, and a check that can be
    wrong about what "does something" means is worse here than one that
    can only be wrong about an empty file.
    """
    content = source(WORKFLOW_RECIPE)
    checked = 0
    # The command string is NOT required to end at the wrapper's name.
    # Two registered actions forward arguments -- `bash tests/x.sh \"$@\"`
    # -- and a pattern anchored on the closing quote silently skipped both,
    # so each could be reduced to comments and still pass this file. That is
    # the same defect this function exists to forbid, one level up, and it
    # was found by emptying a wrapper the pattern did not match and watching
    # the whole script report success.
    for match in re.finditer(r'command = "bash (tests/[^"\s]+\.sh)', content):
        rel = match.group(1)
        wrapper = ROOT / rel
        if not wrapper.is_file():
            raise AssertionError(
                f"a registered action runs {rel}, which does not exist"
            )
        body = []
        for line in source(wrapper).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith(("set -", "shopt ")):
                continue
            body.append(stripped)
        if not body:
            raise AssertionError(
                f"{rel} is registered as a build target but contains no "
                "executable statement: it would exit 0 having tested "
                "nothing, which is worse than failing"
            )
        checked += 1
    if checked < 20:
        raise AssertionError(
            "expected at least 20 registered bash wrappers, found "
            f"{checked}; the scan found too little to be meaningful"
        )


def require_nim_gate_declarations() -> None:
    """A registered Nim gate must be runnable BY THE ENGINE.

    A build action's PATH carries exactly the tool identities the action
    declares. Four registered gates used to declare only ``bash`` while
    shelling out to ``nim`` (and coreutils, and a C++ compiler), so every
    one of them exited 2 before testing anything under ``repro build`` and
    passed only from a development shell that happened to carry the tools.
    This check keeps the next Nim gate from being added the same way:

      * every wrapper that compiles Nim routes through tests/nim-gate.sh --
        or, for the GuiAssert gates, re-execs into a pinned ``nix develop``
        shell and declares ``nix``;
      * the registered action names every identity the wrapper's tool
        contract asks for;
      * every declared name is also in the package's ``uses:`` block, since
        a ``uses:`` entry is what gives the resolver something to resolve;
      * tests/nim-gate.sh is an input of every action that sources it; and
      * the helper's missing-tool path FAILS rather than skips.
    """
    if not NIM_GATE_HELPER.is_file():
        raise AssertionError(f"the shared Nim gate preamble is missing: {NIM_GATE_HELPER}")

    helper = source(NIM_GATE_HELPER)
    failure = re.search(
        r"nim_gate_declaration_failure\(\)\s*\{(?P<body>.*?)\n\}",
        helper,
        flags=re.DOTALL,
    )
    if failure is None:
        raise AssertionError(
            "tests/nim-gate.sh has no nim_gate_declaration_failure; the one "
            "place a missing tool is reported must stay one place"
        )
    body = failure.group("body")
    if not re.search(r"^\s*exit\s+[1-9]", body, flags=re.MULTILINE):
        raise AssertionError(
            "tests/nim-gate.sh's missing-tool path does not exit non-zero. A "
            "missing tool is a declaration bug and must be a LOUD FAILURE; "
            "turning it into a skip would convert every Nim gate into a "
            "silent pass, which is strictly worse than a gate that fails."
        )
    # Prose about not skipping is fine; emitting a skip marker or calling a
    # `skip` helper is the regression this rejects.
    if re.search(r"(?i)\[\s*skip\s*\]", body) or re.search(
        r"(?m)^\s*skip\b", body
    ):
        raise AssertionError(
            "tests/nim-gate.sh's missing-tool path reports a SKIP; a missing "
            "tool must fail, never skip"
        )
    for banned in ["exit 0", "return 0"]:
        if banned in body:
            raise AssertionError(
                f"tests/nim-gate.sh's missing-tool path contains `{banned}`"
            )
    # Every tool check must route to that one failure path. A check that
    # quietly returns success when its tool is absent is the same regression
    # wearing a different hat.
    for probe in ["nim_gate_require", "nim_gate_require_any", "nim_gate_c_compiler"]:
        match = re.search(
            rf"{probe}\(\)\s*\{{(?P<body>.*?)\n\}}", helper, flags=re.DOTALL
        )
        if match is None:
            raise AssertionError(f"tests/nim-gate.sh has no {probe}")
        if "nim_gate_declaration_failure" not in match.group("body"):
            raise AssertionError(
                f"tests/nim-gate.sh's {probe} does not report a missing tool "
                "through nim_gate_declaration_failure; a missing tool must be a "
                "loud failure, never a silent success"
            )

    # Routing to the failure path is necessary but not sufficient: a skip
    # added ALONGSIDE it -- an early `exit 0` in a probe's loop, or one in
    # `nim_gate_run`, which is not one of the probes above -- would leave
    # every check above satisfied while turning the gate into a silent pass.
    # The helper's executable code therefore carries no success exit and no
    # skip marker at all; the only exits it has are the failure path's.
    helper_code = "\n".join(
        line for line in helper.splitlines() if not line.lstrip().startswith("#")
    )
    for banned, why in [
        (r"\bexit\s+0\b", "exits 0"),
        (r"(?i)\[\s*skip\s*\]", "prints a skip marker"),
    ]:
        if re.search(banned, helper_code):
            raise AssertionError(
                f"tests/nim-gate.sh {why}. The helper has exactly one exit "
                "besides the compiled test's own status, and it is the "
                "non-zero declaration failure. A skip path anywhere in here "
                "turns every Nim gate into a silent pass, which is the "
                "regression this check exists to forbid."
            )
    # And the compiled test's status must BE the gate's status: an unguarded
    # final invocation, with nothing swallowing it.
    if not re.search(r'(?m)^\s*"\$checker"\s*$', helper_code):
        raise AssertionError(
            "tests/nim-gate.sh does not run the compiled checker as a final, "
            "unguarded statement. Its exit status is the gate's result; "
            "guarding it (`|| true`) would report success without the test."
        )

    content = source(WORKFLOW_RECIPE)
    declared_uses = set(uses_dependencies(WORKFLOW_RECIPE))
    checked = 0
    for wrapper in nim_gate_wrappers():
        text = source(wrapper)
        rel = wrapper.relative_to(ROOT).as_posix()
        binding, call = action_call_for_command(content, rel)
        identities = declared_identities(content, binding)
        if not sources_nim_gate_helper(text):
            # The GuiAssert gates are the one sanctioned alternative: they
            # re-exec into a pinned `nix develop` shell, so `nix` is the
            # only identity their action needs.
            if re.search(r'\bdevelop\s+"path:', text) is None:
                raise AssertionError(
                    f"{rel} compiles Nim without sourcing tests/nim-gate.sh and "
                    "without re-execing through `nix develop`; the Nim gate "
                    "preamble has exactly one home"
                )
            if "nix" not in identities:
                raise AssertionError(
                    f"{binding} runs {rel}, which re-execs through `nix develop`, "
                    "but does not declare the `nix` tool identity"
                )
            checked += 1
            continue
        if '"tests/nim-gate.sh"' not in call:
            raise AssertionError(
                f"{binding} runs {rel}, which sources tests/nim-gate.sh, but does "
                "not declare it as an input"
            )
        code = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        for banned, why in [
            (r"\bexit\s+0\b", "exits 0 on a branch of its own"),
            (r"\[\s*skip\s*\]", "prints a skip marker"),
        ]:
            if re.search(banned, code):
                raise AssertionError(
                    f"{rel} {why}. A Nim gate wrapper is a tool contract: it "
                    "either runs the gate or fails. Reporting success without "
                    "running it is the regression the engine-level negative gate exists "
                    "to catch; artifact skips belong in the Nim test, tool "
                    "checks belong in tests/nim-gate.sh and must fail."
                )
        for requirement in sorted(required_identities(wrapper)):
            alternatives = set(requirement.split("|"))
            if not alternatives & identities:
                raise AssertionError(
                    f"{binding} runs {rel}, whose tool contract needs "
                    f"{' or '.join(sorted(alternatives))}, but the action declares "
                    f"only: {', '.join(sorted(identities))}. Under `repro build` "
                    "the action's PATH is exactly what it declares, so the gate "
                    "would exit 2 before testing anything."
                )
        for identity in sorted(identities):
            if identity not in declared_uses:
                raise AssertionError(
                    f"{binding} declares the `{identity}` tool identity, but "
                    "`package reproosWorkflows` does not list it in `uses:`; the "
                    "resolver has nothing to resolve"
                )
        checked += 1
    if checked == 0:
        raise AssertionError("no Nim gate wrappers were checked")


def strip_shell_comments(text: str) -> str:
    """Drop whole-line and trailing `#` comments.

    A substring match against a raw line is satisfied by a comment
    mentioning the thing, which is how a check that reads like an
    assertion about behaviour turns into an assertion about prose. The
    quote tracking is deliberately simple -- these scripts do not put
    `#` inside a quoted string on a line that also matters -- but it is
    there so a `--flag=a#b` is not truncated.
    """
    out = []
    for line in text.splitlines():
        quote = ""
        cut = None
        for i, ch in enumerate(line):
            if quote:
                if ch == quote:
                    quote = ""
            elif ch in "'\"":
                quote = ch
            elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
                cut = i
                break
        out.append(line if cut is None else line[:cut])
    return "\n".join(out)


def shell_if_block(content: str, opener: str, subject: str) -> str:
    """The body of one `if ... then` .. `fi`, and nothing after it.

    Scoped by counting nested `if`/`fi` rather than scanning forward for
    the first terminator. A forward scan runs past the construct under
    test into whatever is below it, which is how a check keeps passing
    after the thing it was written for has been deleted.
    """
    lines = strip_shell_comments(content).splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == opener:
            start = i
            break
    if start is None:
        raise AssertionError(f"{subject}: no `{opener}` in the script")
    depth = 1
    for i in range(start + 1, len(lines)):
        stripped = lines[i].strip()
        if stripped.startswith("if ") or stripped == "if":
            depth += 1
        elif stripped == "fi" or stripped.startswith("fi "):
            depth -= 1
            if depth == 0:
                return "\n".join(lines[start + 1 : i])
    raise AssertionError(f"{subject}: `{opener}` is never closed")


def shell_assignments(content: str, name: str) -> list[str]:
    """EVERY assignment of a shell variable, in order.

    Reading only the first is defeated by leaving the real one where it
    is and adding a decoy below it, which is the value the script
    actually runs with. `export`, `local`, `readonly`, `declare` and
    `typeset` are stripped first, because `export NAME=v` assigns
    exactly as `NAME=v` does.
    """
    values = []
    pattern = re.compile(
        r"^\s*(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)?|typeset\s+)*"
        + re.escape(name)
        + r"=(?P<value>.*)$"
    )
    for line in strip_shell_comments(content).splitlines():
        match = pattern.match(line)
        if match is not None:
            values.append(match.group("value").strip())
    return values


def nim_seq_block(content: str, anchor: str, subject: str) -> str:
    """One `@[ ... ]` literal, starting at `anchor`, bracket-matched.

    Same reason as `shell_if_block`: the recipe has several
    `extraInputs = @[...]` blocks and a check that read past the end of
    one would be satisfied by another action's inputs.
    """
    start = content.find(anchor)
    if start < 0:
        raise AssertionError(f"{subject}: `{anchor}` is not in the recipe")
    open_at = content.find("@[", start)
    if open_at < 0:
        raise AssertionError(f"{subject}: `{anchor}` opens no sequence literal")
    depth = 0
    for i in range(open_at + 2, len(content)):
        if content[i] == "[":
            depth += 1
        elif content[i] == "]":
            if depth == 0:
                return content[open_at + 2 : i]
            depth -= 1
    raise AssertionError(f"{subject}: the sequence literal is never closed")


def require_attestation_agent_installed() -> None:
    """The attestation agent reaches the integrity-checked root.

    Every check below reads a VALUE or a scoped construct, never a name
    appearing somewhere in a file, because the whole class of failure
    this guards against is a phase that was deleted or renamed while the
    words describing it stayed behind.

    None of this proves the agent RUNS. That needs a boot, which this
    gate does not perform. What it establishes is that the recipe
    installs the binary, takes the unit from the binary rather than
    keeping a second copy of it, enables it on a path the running
    systemd searches, and declares the binary as an input so that
    rebuilding the agent invalidates the root it went into.
    """
    configure = ROOT / "recipes/reproos-image/scripts/configure-installed-root.sh"
    stager = ROOT / "recipes/reproos-image/scripts/stage-installed-root.sh"
    subject = "attestation agent installation"

    configure_text = source(configure)

    # The two variables the phase runs on. Every assignment is read, and
    # more than one is the ambiguity it looks like.
    for name, wants in (
        ("ATTESTATION_AGENT_BIN", "REPROOS_ATTESTATION_AGENT_BIN"),
        ("ATTESTATION_TIER", "REPROOS_ATTESTATION_TIER"),
    ):
        assignments = shell_assignments(configure_text, name)
        if len(assignments) != 1:
            raise AssertionError(
                f"{subject}: {name} is assigned {len(assignments)} times "
                f"({assignments}); exactly one assignment decides what the "
                f"phase runs with"
            )
        if wants not in assignments[0]:
            raise AssertionError(
                f"{subject}: {name} is {assignments[0]}, which does not come "
                f"from {wants}; the caller would have no way to set it"
            )

    body = shell_if_block(
        configure_text, 'if [ -n "$ATTESTATION_AGENT_BIN" ]; then', subject
    )

    # The binary lands where the unit will look for it. The destination is
    # CAPTURED rather than pinned twice, because the unit's `--binary` is
    # checked against this same value below: the two are one path spelled
    # in two places, and a check that pinned each of them separately would
    # pass on a pair that no longer agree.
    binary_install = re.search(
        r'install\s+-m\s+0755\s+"\$ATTESTATION_AGENT_BIN"\s*\\?\s*\n?\s*'
        r'"\$ROOT_TREE/(?P<dest>\S+?)"',
        body,
    )
    if binary_install is None or binary_install.group("dest") != (
        "usr/bin/attestation-agent"
    ):
        raise AssertionError(
            f"{subject}: the phase never installs the agent at "
            f"/usr/bin/attestation-agent"
        )
    installed_binary = "/" + binary_install.group("dest")

    # The unit comes FROM the binary. A heredoc here would be a second
    # copy of the daemon's command line, which is the drift this avoids.
    render = re.search(
        r'"\$ATTESTATION_AGENT_BIN"\s+systemd-unit'
        r"(?P<args>(?:[^\n]*\\\n)*[^\n]*)",
        body,
    )
    if render is None:
        raise AssertionError(
            f"{subject}: the phase does not ask the agent for its own unit; a "
            f"unit written here is a second spelling of the daemon's flags"
        )
    render_args = render.group("args")

    # `--binary` decides the ExecStart the machine will run, and it has to
    # be the path the install above actually wrote to. An install and a
    # unit pointing at different paths still builds, still installs and
    # still boots -- and the agent never starts.
    binary_flag = re.search(r"--binary=(?P<path>\S+)", render_args)
    if binary_flag is None:
        raise AssertionError(
            f"{subject}: the unit is rendered without --binary, so its "
            f"ExecStart is whatever the agent's default happens to be"
        )
    if binary_flag.group("path") != installed_binary:
        raise AssertionError(
            f"{subject}: the unit is rendered with --binary="
            f"{binary_flag.group('path')} but the binary is installed at "
            f"{installed_binary}; the unit would name a path nothing put a "
            f"binary at"
        )

    # And the tier reaches the render. Reading only the assignment of
    # ATTESTATION_TIER says the caller CAN set it; it says nothing about
    # whether anything consumes it, and a tier that never reaches the
    # daemon is a daemon running on whichever tier it defaults to.
    if not re.search(r'--tier="\$ATTESTATION_TIER"', render_args):
        raise AssertionError(
            f"{subject}: the unit is rendered without --tier=\"$ATTESTATION_TIER\", "
            f"so REPROOS_ATTESTATION_TIER is set by the caller and read by "
            f"nothing"
        )

    if "<<" in body:
        raise AssertionError(
            f"{subject}: the phase carries a heredoc, so it is writing a unit "
            f"rather than taking the one the binary renders"
        )

    # `usr/lib/systemd/system`, not `lib/systemd/system`. The value is
    # checked rather than the presence of the word `systemd`, because the
    # legacy path is a live spelling that silently never loads.
    unit_install = re.search(
        r'install\s+-m\s+0644\s+\S+\s*\\?\s*\n?\s*'
        r'"\$ROOT_TREE/(?P<dest>\S+?)"',
        body,
    )
    if unit_install is None:
        raise AssertionError(f"{subject}: the phase never installs a unit file")
    if unit_install.group("dest") != "usr/lib/systemd/system/attestation-agent.service":
        raise AssertionError(
            f"{subject}: the unit is installed at "
            f"{unit_install.group('dest')}; current systemd searches "
            f"usr/lib/systemd/system and a unit anywhere else is never found"
        )

    # And it is enabled, by a link whose TARGET is that same file.
    enable = re.search(
        r'ln\s+-sfn\s+(?P<target>\S+)\s*\\?\s*\n?\s*'
        r'"\$ROOT_TREE/(?P<link>\S+?)"',
        body,
    )
    if enable is None:
        raise AssertionError(f"{subject}: the unit is installed but never enabled")
    if enable.group("target") != "/usr/lib/systemd/system/attestation-agent.service":
        raise AssertionError(
            f"{subject}: the enable symlink points at {enable.group('target')}, "
            f"not at the unit that was installed"
        )
    if enable.group("link") != (
        "etc/systemd/system/multi-user.target.wants/attestation-agent.service"
    ):
        raise AssertionError(
            f"{subject}: the enable symlink is at {enable.group('link')}, which "
            f"is not a directory systemd starts units from"
        )

    # The caller has to be able to reach the phase at all.
    stager_text = strip_shell_comments(source(stager))
    call = re.search(
        r"(?P<env>(?:^\s*\w+=\S*\s*\\\n)+)\s*bash\s+"
        r'"\$SCRIPT_DIR_SELF/configure-installed-root\.sh"',
        stager_text,
        re.MULTILINE,
    )
    if call is None:
        raise AssertionError(
            f"{subject}: the stager's call to configure-installed-root.sh has no "
            f"environment prefix to read"
        )
    if "REPROOS_ATTESTATION_AGENT_BIN=" not in call.group("env"):
        raise AssertionError(
            f"{subject}: the stager does not pass REPROOS_ATTESTATION_AGENT_BIN "
            f"to configure-installed-root.sh, so the phase can never run"
        )

    # The recipe resolves the binary, hands it over, and -- the part that
    # matters for reproducibility -- declares it as a typed input, so a
    # rebuilt agent invalidates the root it was installed into.
    recipe_text = source(IMAGE_RECIPE)
    if not re.search(
        r'attestationAgentInput\s*=\s*absolutePath\(\s*\n?\s*'
        r'reprobuildRoot\s*/\s*"build"\s*/\s*"bin"\s*/\s*"attestation-agent"',
        recipe_text,
    ):
        raise AssertionError(
            f"{subject}: the recipe does not resolve the agent from the "
            f"reprobuild checkout's build/bin"
        )
    stager_command = nim_seq_block(
        recipe_text, "let stageInstalledRootCommand", subject
    )
    # The VALUE, not merely the name. `REPROOS_ATTESTATION_AGENT_BIN=` set
    # to some other resolved path -- the engine binary, say -- installs a
    # different program as the attestation agent, and a check that read
    # only the assignment's left-hand side would call that a pass.
    handed_over = re.search(
        r'"REPROOS_ATTESTATION_AGENT_BIN=" &\s*\n?\s*'
        r"quoteShellPosix\((?P<value>\w+)\)",
        stager_command,
    )
    if handed_over is None:
        raise AssertionError(
            f"{subject}: the staging command does not set "
            f"REPROOS_ATTESTATION_AGENT_BIN"
        )
    if handed_over.group("value") != "attestationAgentInput":
        raise AssertionError(
            f"{subject}: the staging command hands "
            f"{handed_over.group('value')} to REPROOS_ATTESTATION_AGENT_BIN, "
            f"not the resolved agent binary; the image would install a "
            f"different program under the agent's name"
        )
    stager_inputs = nim_seq_block(recipe_text, "extraInputs = @[\n          \"recipes/reproos-image/scripts/stage-installed-root.sh\"", subject)
    if "attestationAgentInput" not in stager_inputs:
        raise AssertionError(
            f"{subject}: the staging action does not declare the agent binary as "
            f"an input, so rebuilding the agent would not rebuild the root that "
            f"contains it"
        )


def main() -> None:
    modules = [
        ROOT_RECIPE,
        INSTALLER_RECIPE,
        ISO_RECIPE,
        IMAGE_RECIPE,
        CONTAINER_RECIPE,
        WORKFLOW_RECIPE,
        PACKAGE_SETS,
    ]
    for path in modules:
        if not path.is_file():
            raise AssertionError(f"canonical Reprobuild module missing: {path}")

    package_modules = [
        ROOT_RECIPE,
        INSTALLER_RECIPE,
        ISO_RECIPE,
        IMAGE_RECIPE,
        CONTAINER_RECIPE,
        WORKFLOW_RECIPE,
    ]
    for path in package_modules:
        if 'defaultToolProvisioning "from-source"' not in source(path):
            raise AssertionError(f"package does not default to from-source tools: {path}")
    if "shell(" in source(ROOT_RECIPE) or "command =" in source(ROOT_RECIPE):
        raise AssertionError("root repro.nim must remain a composition manifest")
    for path in [ISO_RECIPE, IMAGE_RECIPE, CONTAINER_RECIPE, WORKFLOW_RECIPE]:
        require_shell_action_contracts(path)
    require_registered_wrappers_do_something()
    require_contains(
        ISO_RECIPE,
        ['"xorriso"', '"mtools"', '"squashfs-tools"'],
        "ISO source authoring tool interface",
    )

    obsolete = [
        ROOT / "Justfile",
        ROOT / "apps/reproos-installer/repro.nim",
        ROOT / "recipes/reproos-iso/repro.nim",
        ROOT / "recipes/reproos-image/repro.nim",
    ]
    for path in obsolete:
        if path.exists():
            raise AssertionError(f"obsolete parallel contributor interface remains: {path}")

    require_contains(
        ROOT_RECIPE,
        [
            "installerPackage.buildReproosInstallerPackage()",
            "isoPackage.buildReproosIsoPackage()",
            "imagePackage.buildReproosImagePackage()",
            "containerPackage.buildReproosContainerPackage()",
            "workflows.buildReproosWorkflowsPackage()",
            'collect("default"',
        ],
        "root graph",
    )

    require_contains(
        INSTALLER_RECIPE,
        [
            'ReproosInstallerReadyActionId* = "install-mirror-reproosInstaller"',
            '".repro/output/install/usr/bin/reproos-installer"',
            "BuildActionDef(id: ReproosInstallerReadyActionId)",
            '"cmake >=3.24"',
            "freshConfigure = true",
        ],
        "finalized installer package contract",
    )
    require_contains(
        IMAGE_RECIPE,
        [
            'let reproCliInput = absolutePath(',
            'reprobuildRoot / "build" / "bin" / "repro", projectRoot)',
            '"REPRO_BIN=" & quoteShellPosix(reproCliInput)',
            "reproCliInput,",
        ],
        "pinned image assembly CLI",
    )

    require_contains(
        ROOT / "tests/test-installed-desktop-screenshot.sh",
        ['--screenshot-delay-sec "${REPROOS_SCREENSHOT_DELAY_SEC:-20}"'],
        "installed desktop graphical settle gate",
    )
    require_contains(
        ROOT / "tests/test-installer-vm-screenshot.sh",
        ['--screenshot-delay-sec "${REPROOS_SCREENSHOT_DELAY_SEC:-5}"'],
        "installer VM graphical settle gate",
    )
    installer_consumers = [
        WORKFLOW_RECIPE,
        ISO_RECIPE,
        IMAGE_RECIPE,
        CONTAINER_RECIPE,
        ROOT / "tools/installer-dev-runtime.sh",
        ROOT / "tests/test-installer-artifacts.sh",
        ROOT / "tests/test-unattended-install.sh",
        ROOT / "recipes/reproos-iso/scripts/stage-de-rootfs.sh",
        ROOT / "recipes/reproos-image/scripts/build-reproos-image.sh",
    ]
    for path in installer_consumers:
        content = source(path)
        if "ReproosInstallerInstallActionId" in content:
            raise AssertionError(f"installer consumer bypasses finalization: {path}")
        if "build/reproos-installer/out/usr/bin/reproos-installer" in content:
            raise AssertionError(f"installer consumer uses raw CMake output: {path}")

    for path in modules[1:]:
        content = source(path)
        if "devEnv:" in content and path != WORKFLOW_RECIPE:
            raise AssertionError(f"package module duplicates workflows through devEnv: {path}")
        if re.search(r"M9\.[A-Za-z0-9.]+", content) or "historical" in content.lower():
            raise AssertionError(f"package module contains stale plan-ID archaeology: {path}")

    iso_dependencies = build_dependencies(ISO_RECIPE)
    image_dependencies = build_dependencies(IMAGE_RECIPE)
    canonical_dependencies = canonical_rootfs_packages()
    require_unique(iso_dependencies, "ISO buildDeps")
    require_unique(image_dependencies, "image buildDeps")
    require_unique(canonical_dependencies, "canonical rootfs package set")
    if iso_dependencies != image_dependencies:
        raise AssertionError("ISO and image source package closures differ")
    if iso_dependencies != canonical_dependencies:
        raise AssertionError("buildDeps blocks differ from the canonical rootfs package set")
    if "reproos-installer" in iso_dependencies:
        raise AssertionError("the installer must be an action dependency, not a source package")

    workflow_dependencies = uses_dependencies(WORKFLOW_RECIPE)
    require_unique(workflow_dependencies, "workflow uses")
    if "vm-harness" not in workflow_dependencies:
        raise AssertionError(
            "workflow uses must select the federated vm-harness producer"
        )
    if "nix" not in workflow_dependencies:
        raise AssertionError("workflow uses must provide GuiAssert's environment launcher")

    workflow_content = source(WORKFLOW_RECIPE)
    declared_tasks = set(re.findall(r'\btask\("([^"]+)"', workflow_content))
    declared_runs = set(re.findall(r'\brun\("([^"]+)"', workflow_content))
    if declared_tasks & declared_runs:
        raise AssertionError("a workflow is duplicated as a task and a run edge")
    manual_vm_tasks = {f"vm-{operation}" for operation in [
        "ssh", "exec", "status", "logs", "stop", "destroy",
    ]}
    if not manual_vm_tasks.issubset(declared_tasks):
        raise AssertionError("manual VM commands must be tasks with inherited streams")
    for task_name in manual_vm_tasks:
        if not re.search(
            rf'task\("{task_name}",\s*command = withHostVmRuntime\(',
            workflow_content,
        ):
            raise AssertionError(f"VM task {task_name} must select the host VM runtime")
    require_contains(ROOT_RECIPE, ["workflows.devEnvReproosWorkflowsPackage()"],
                     "interactive workflow composition")
    for action_name in [
        "testInstallerVisuals",
        "inspectInstallerVmFrame",
        "captureInstallerVmScreenshot",
        "e2eUnattendedVmInstall",
        "testInstalledDesktop",
    ]:
        match = re.search(
            rf"let {action_name} = shell\(.*?\.withToolIdentities\(\[(.*?)\]\)",
            workflow_content,
            flags=re.DOTALL,
        )
        if match is None or '"nix"' not in match.group(1):
            raise AssertionError(
                f"GuiAssert action {action_name} does not declare the nix tool"
            )
    for action_name in [
        "captureInstallerVmScreenshot", "testVmIncusParity", "bootIso",
        "installVm", "installedVm", "verifyInstalledVmBoot",
        "e2eUnattendedVmInstall", "e2eVmPersistentLifecycle",
        "testVmSshHostKeyMismatch",
        "testIso", "bootImage", "testImageHealth", "testInstalledDesktop",
        "sshImage", "testInstalledSsh",
    ]:
        if not re.search(
            rf"let {action_name} = shell\(\s*command = withHostVmRuntime\(",
            workflow_content,
        ):
            raise AssertionError(
                f"VM action {action_name} must select the available libvirt runtime"
            )
    require_contains(
        WORKFLOW_RECIPE,
        [
            "command -v libvirtd",
            "libvirtd -d",
            "libvirt session did not start",
            'export LIBVIRT_DEFAULT_URI=qemu:///session',
            'unset LD_LIBRARY_PATH DYLD_LIBRARY_PATH',
            '${REPROOS_VM_STATE_DIR:-}',
            '${REPROOS_VM_BACKEND:-}',
            '${REPROOS_VM_ACCELERATION:-}',
            '${REPROOS_UNATTENDED_ISO:-}',
            '${REPROOS_VM_HARNESS_BIN:-}',
            '${VM_HARNESS_BIN:-}',
            '${GUI_ASSERT_ROOT:-}',
            '${SSH_KEYGEN_BIN:-}',
            '${XORRISO_BIN:-}',
            '"boot-iso"',
            '"test-iso"',
            '"boot-image"',
            'task("vm-ssh",',
            'useTool("ssh")',
            '"ssh-keygen"',
            'command = withHostVmRuntime("python3 tools/reproos-vm.py ssh --")',
            'command = withHostVmRuntime("python3 tools/reproos-vm.py exec --")',
        ],
        "host VM runtime fallback",
    )
    if '"openssh"' in workflow_content:
        raise AssertionError(
            "host workflows must select ssh/ssh-keygen commands, not the guest openssh package"
        )
    if workflow_content.index("unset LD_LIBRARY_PATH DYLD_LIBRARY_PATH;") > (
        workflow_content.index("libvirtd -d;")
    ):
        raise AssertionError("guest library paths must be cleared before libvirt startup")

    require_contains(
        WORKFLOW_RECIPE,
        [
            *[f'target("{name}"' for name in [
                "test-source-composition",
                "test-installer-preview",
                "test-installer-visuals",
                "test-installer-artifacts",
                "test_remote_access_configuration_validation",
                "test_instance_secrets_do_not_affect_public_image_cache_key",
                "test_unattended_vm_rejects_live_media_false_positive",
                "test-cache-backfill",
                "test-incus-projection",
                "test-incus-helper",
                "test-incus-publication",
                "test-incus-second-host",
                "test-vm-incus-parity-checker",
                "test-incus-lifecycle",
                "test-incus-parallel-isolation",
                "test-incus-reproducibility",
                "test-vm-incus-parity",
                "test-iso",
                "test-image-health",
                "test-installed-desktop",
                "test-installed-ssh",
                "test-unattended-install",
                "e2e_unattended_vm_installs_and_boots_target_disk",
                "e2e_vm_persistent_lifecycle",
                "test_vm_ssh_host_key_mismatch_fails_closed",
            ]],
            *[f'run("{name}"' for name in [
                "installer",
                "installer-screenshots",
                "installer-accept-goldens",
                "installer-vm-screenshot",
                "cache-backfill",
                "boot-iso",
                "vm-install",
                "vm-installed",
                "vm-verify-installed-boot",
                "boot-image",
                "image-ssh",
                "incus-import",
                "incus-launch",
                "incus-shell",
                "incus-logs",
                "incus-destroy",
                "incus-publish",
                "incus-pull",
            ]],
            'collect("lint"',
            'collect("incus-remote-acceptance"',
        ],
        "workflow module",
    )

    require_contains(
        WORKFLOW_RECIPE,
        [
            'actionId = "reproos.e2e-unattended-vm-install"',
            'actionId = "reproos.test-vm-ssh-host-key-mismatch"',
            "deps = @[e2eUnattendedVmInstall.id]",
            "deps = @[e2eVmPersistentLifecycle.id]",
            "e2eUnattendedVmInstall)",
            "testVmSshHostKeyMismatch)",
        ],
        "unattended VM acceptance edge split",
    )

    require_contains(
        WORKFLOW_RECIPE,
        [
            "tools/capture-installer-screens.sh",
            "tools/run-installer-preview.sh",
            "tools/installer-dev-runtime.sh",
            "tests/test-installer-preview.sh",
            "tests/test-installer-visuals.sh",
            "tests/test_installer_visuals.nim",
            "tests/test-installer-vm-screenshot.sh",
            "tests/test-installer-vm-frame.sh",
            "tests/test_installer_vm_frame.nim",
            "tests/test-installer-artifacts.sh",
            "tests/test_machine_config.py",
            "tests/test_reproos_vm.py",
            "tests/e2e-unattended-vm-installs.sh",
            "tests/test-vm-ssh-host-key-mismatch.sh",
            "tools/reproos-machine-config.py",
            "tools/reproos-vm.py",
            "tests/fixtures/instance-enrollment.toml",
            "tests/test_cache_reproos_packages.py",
            "tests/test_incus_projection.py",
            "tests/test_reproos_incus_helper.py",
            "tests/test_incus_publication.py",
            "tests/test-incus-second-host.sh",
            "tests/remote-incus-acceptance.sh",
            "tests/test-incus-lifecycle.sh",
            "tests/test-incus-parallel-isolation.sh",
            "tests/test-incus-image-reproducibility.sh",
            "tests/test-vm-incus-parity.sh",
            "tests/check_vm_incus_parity.py",
            "tests/test_vm_incus_parity_checker.py",
            "tools/reproos-incus.sh",
            "tools/reproos-incus-publication.py",
            "tools/cache_reproos_packages.py",
            "tests/test-installed-image-health.sh",
            "tests/test-installed-desktop-screenshot.sh",
            "tests/test-installed-desktop-frame.sh",
            "tests/test_installed_desktop_frame.nim",
            "tests/test-installed-ssh.sh",
            "tests/test-unattended-install.sh",
            "tests/fixtures/auto-config-minimal.toml",
        ],
        "declared workflow inputs",
    )

    require_contains(
        ROOT / "tests/test-vm-incus-parity.sh",
        ["test -s /run/reproos/healthy"],
        "VM and Incus parity health contract",
    )

    require_contains(
        INSTALLED_SSH_TEST,
        [
            "--guest linux",
            "--graphics vnc",
            "--video virtio",
            "--expect 'REPROOS_HEALTH:PASS'",
            "--ssh-forward-port auto",
        ],
        "installed SSH graphical boot contract",
    )
    require_contains(
        INCUS_LIFECYCLE_TEST,
        ['bash "$tool" launch', 'bash "$tool" destroy'],
        "portable Incus helper invocation",
    )

    require_contains(
        CONTRIBUTOR_GUIDE,
        ["repro lint", "stable action IDs", "executable identities"],
        "contributor graph-quality policy",
    )
    require_contains(
        CONTRIBUTOR_GUIDE,
        [
            "repro build incus-image",
            "repro build incus-acceptance",
            "repro build incus-remote-acceptance",
            "repro run incus-launch",
            "repro run incus-publish",
            "incus-destroy",
        ],
        "contributor Incus workflow",
    )
    require_contains(
        README,
        [
            "repro build incus-projection",
            "repro build incus-image",
            "repro build incus-acceptance",
            "repro build incus-remote-acceptance",
            "repro run incus-launch",
            "repro run incus-publish",
            "repro run incus-pull",
            "repro run incus-destroy",
        ],
        "documented Incus command surface",
    )
    require_contains(
        CONTAINER_GUIDE,
        [
            "REPRO_AUTO_CONFIG",
            "REPROOS_INCUS_PROJECT",
            "VMH_INCUS_CMD",
            "test-incus-reproducibility",
            "test-incus-publication",
            "test-incus-second-host",
            "test-vm-incus-parity",
        ],
        "Incus operator guide",
    )
    require_contains(
        ROOT / "tests/remote-incus-acceptance.sh",
        [
            "user.reproos.acceptance",
            "/etc/subuid",
            "config device override",
            "busybox ping",
            "http://$server_ip:8080/response",
            "undeclared application port 8081 is reachable",
            "remote_host=",
        ],
        "second-host Incus acceptance",
    )
    require_contains(README, ["repro lint"], "README quality command")
    require_contains(
        ROOT / "config.nims",
        [
            "if not defined(reproVendoredHash):",
            'switch("import", "reproos_vendored_hash_runtime")',
        ],
        "single vendored hash runtime scheduling",
    )

    iso_content = source(ISO_RECIPE)
    if re.search(r"vendor/(vmlinuz|initrd)", iso_content):
        raise AssertionError("ISO recipe still references a vendored kernel or initramfs")
    for value in [
        "reprobuild-packages/packages/source/kernel",
        "reproos-initramfs.img",
        "reproos-iso-disk-initramfs.img",
        "reproos-unattended-disk-initramfs.img",
        "REPRO_BUSYBOX_INSTALL_ROOT",
        "REPRO_DISK_INIT_OUT",
        "REPRO_LIVE_TARGET=graphical",
        'ReproosIsoRootfsActionId* = "reproosIso.stage_rootfs"',
        'extraOutputs = @["build/de-rootfs"]',
        'deps = @[stageRootfsAction.id]',
        'target("rootfs", stageRootfsAction)',
        "setRegisteredActionDependencyPolicy(stageRootfsAction.id",
        "automaticMonitorPolicy(@[rootfsOutputAbs])",
        "setRegisteredActionDependencyPolicy(buildIsoAction.id",
        "diskInitramfsOutputAbs",
        "unattendedDiskInitramfsOutputAbs",
        "reproCliInput",
    ]:
        if value not in iso_content:
            raise AssertionError(f"ISO recipe is missing source-build input: {value}")

    initramfs_tools = {"cpio", "find", "gzip", "sed"}
    for path in [ISO_RECIPE, IMAGE_RECIPE, WORKFLOW_RECIPE]:
        declared_dependencies = set(uses_dependencies(path))
        if path != WORKFLOW_RECIPE:
            declared_dependencies.update(build_dependencies(path))
        missing = sorted(initramfs_tools - declared_dependencies)
        if missing:
            raise AssertionError(
                f"{path} does not declare its initramfs tools: {', '.join(missing)}"
            )
    for path, binding in [
        (ISO_RECIPE, "buildIsoAction"),
        (ISO_RECIPE, "buildUnattendedIsoAction"),
        (IMAGE_RECIPE, "buildDiskInitrdAction"),
    ]:
        require_registered_action_tools(path, binding, initramfs_tools)

    image_content = source(IMAGE_RECIPE)
    for value in [
        'import "../reproos-iso/package" as isoPackage',
        'ReproosDiskInitrdActionId* = "reproosImage.build_disk_initrd"',
        'target("disk-initramfs", buildDiskInitrdAction)',
        "isoPackage.ReproosIsoRootfsActionId",
        "isoPackage.ReproosIsoRootfsOutput",
        "ReproosDiskInitrdOutput",
        "cacheable = false",
        'let imageBuildDirAbs = projectRoot / "recipes/reproos-image/build"',
        "setRegisteredActionDependencyPolicy(buildImageAction.id",
        "automaticMonitorPolicy(@[imageBuildDirAbs])",
    ]:
        if value not in image_content:
            raise AssertionError(
                f"image recipe is missing output dependency exclusion: {value}"
            )

    # The image build has two halves, and each of these values has to be
    # in the half that owns it. The DRIVER installs a disk; the CONFIGURE
    # script fills in the installed root, and reads the validated config
    # through the one shared parser. Naming the file each value belongs to
    # is what keeps the split from becoming two implementations.
    image_script = source(
        ROOT / "recipes/reproos-image/scripts/build-reproos-image.sh"
    )
    configure_script = source(
        ROOT / "recipes/reproos-image/scripts/configure-installed-root.sh"
    )
    image_config_script = source(
        ROOT / "recipes/reproos-image/scripts/image-config.sh"
    )
    for value in [
        "REPROOS_STAGED_ROOTFS",
        "REPROOS_DISK_INITRD",
        '--kernel "$SOURCE_KERNEL"',
        '--initrd "$DISK_INITRD"',
    ]:
        if value not in image_script:
            raise AssertionError(f"image driver is missing graph input: {value}")
    for value in [
        '\\$1 != g && \\$1 != \\"live\\" && \\$3 != gid',
        'END { exit(found ? 0 : 1) }',
    ]:
        if value not in configure_script:
            raise AssertionError(
                f"installed-root configuration is missing graph input: {value}"
            )
    for value in [
        'USER_FULL_NAME="$(toml_get "$CFG" "user" "full_name")"',
    ]:
        if value not in image_config_script:
            raise AssertionError(
                f"shared image config reader is missing graph input: {value}"
            )
    # There is ONE reader of the validated config. A second copy of the
    # parsing in either half would be a second answer to what the image
    # is, and the second answer would be the untested one.
    for path, half in (
        (ROOT / "recipes/reproos-image/scripts/build-reproos-image.sh", image_script),
        (
            ROOT / "recipes/reproos-image/scripts/configure-installed-root.sh",
            configure_script,
        ),
        (
            ROOT / "recipes/reproos-image/scripts/stage-installed-root.sh",
            source(ROOT / "recipes/reproos-image/scripts/stage-installed-root.sh"),
        ),
    ):
        # A DEFINITION, whatever the spacing. `toml_get() {` is one
        # spelling of it; `toml_get ()  {` and a brace on the next line
        # are the same function and used to slip through.
        if re.search(r"(?m)^\s*(function\s+)?toml_get\s*\(\s*\)", half):
            raise AssertionError(
                f"{path} defines its own TOML reader; image-config.sh is the one"
            )
        # A SOURCE LINE, not a mention. Every one of these files names
        # image-config.sh in a shellcheck directive and in its comments,
        # so `not in half` stayed false with the `.` line deleted and the
        # script reading nothing. Same idiom as sources_nim_gate_helper().
        if not re.search(r"(?m)^\s*(\.|source)\s+\S*image-config\.sh", half):
            raise AssertionError(
                f"{path} does not SOURCE the shared image-config.sh reader "
                "(a comment naming it is not a source line)"
            )
    for legacy in ["REPRO_FORCE_RESTAGE", "stage-de-rootfs.sh \"$STAGE_DIR\""]:
        if legacy in image_script:
            raise AssertionError(f"image driver retains private stage cache: {legacy}")

    require_contains(
        ROOT / "recipes/reproos-image/scripts/reproos-health-check",
        [
            "account_gecos",
            "group:$expected_group",
            "gshadow:$expected_group",
            "accounts:installed-identity-only",
            "groups:unique-gids",
            "groups:unique-names",
            "gshadow:unique-names",
        ],
        "installed account health checks",
    )
    require_contains(
        ROOT / "tools/reproos_image_metadata.py",
        ['name == "var/empty"', "mode = 0o755"],
        "OpenSSH privilege-separation directory metadata",
    )
    require_contains(
        ROOT / "recipes/reproos-image/scripts/reproos-first-boot-enroll",
        [
            'groups="$groups seat"',
            'networkmanager) preferred_gid=102',
            'seat) preferred_gid=985',
            'chown -R "$user:$user" "$home"',
            "printf '%s:x:20000:0:99999:7:::",
            "User=$user",
            "Session=sway",
            "auto-config.toml.disabled-after-install",
        ],
        "installed graphical-session enrollment",
    )
    require_contains(
        ISO_RECIPE,
        [
            '"recipes/reproos-image/scripts/reproos-health-check"',
            '"recipes/reproos-image/scripts/reproos-sway.conf"',
        ],
        "ISO rootfs health-check input",
    )
    require_contains(
        STAGE_ROOTFS_SCRIPT,
        [
            "\n  grep\n",
            "libseat",
            "ExecStart=/usr/bin/seatd -g seat",
            "graphical.target.wants/seatd.service",
            "sshd:x:74:74:OpenSSH privilege separation",
            "OpenSSH account name or ID 74 is already in use",
            "recipes/reproos-image/scripts/reproos-health-check",
            "reproos-health-check.service",
            "ConditionPathExists=/var/lib/reproos/installation-receipt.json",
            "link_entry sway swaybar",
            "link_entry sway swaynag",
            "link_entry qt6-declarative qml",
            "recipes/reproos-image/scripts/reproos-sway.conf",
        ],
        "installed ISO health gate",
    )
    health_service_sources = [
        source(STAGE_ROOTFS_SCRIPT),
        source(ROOT / "recipes/reproos-image/scripts/build-reproos-image.sh"),
        source(ROOT / "recipes/reproos-image/scripts/configure-installed-root.sh"),
    ]
    invalid_health_order = (
        "Description=ReproOS post-installation acceptance check\n"
        "After=graphical.target"
    )
    for health_service_source in health_service_sources:
        if invalid_health_order in health_service_source:
            raise AssertionError(
                "health service must not order itself after its owning target"
            )
    require_contains(
        ROOT / "recipes/reproos-image/scripts/reproos-health-check",
        [
            "systemctl get-default",
            "target:graphical-default",
            "service:sshd",
            "service:network",
            "REPROOS_NETWORK_HEALTH_ATTEMPTS",
            "network:ipv4",
            "network:default-route",
        ],
        "graphical target health check",
    )
    require_contains(
        ROOT / "recipes/reproos-image/scripts/reproos-network.service",
        [
            "Before=network.target sshd.service",
            "ExecStart=/usr/local/sbin/reproos-network",
            "ExecStartPost=/usr/local/sbin/reproos-network-wait",
            "TimeoutStartSec=30",
        ],
        "shared DHCP service",
    )
    require_contains(
        ROOT / "recipes/reproos-image/scripts/reproos-network",
        [
            "REPROOS_SYS_CLASS_NET",
            "REPROOS_NETWORK_INTERFACE_ATTEMPTS",
            "REPROOS_NETWORK_READY_FILE",
            "continuing offline",
            "exit 0",
        ],
        "offline-capable DHCP launcher",
    )
    require_contains(
        ROOT / "recipes/reproos-image/scripts/reproos-sway.conf",
        ["ReproOS Desktop", "reproos-desktop.qml", "swaybg_command -"],
        "installed desktop readiness surface",
    )
    require_contains(
        ROOT / "recipes/reproos-image/scripts/reproos-desktop.qml",
        ['title: "ReproOS Desktop"', 'text: "ReproOS"', 'text: "Ready"'],
        "installed desktop QML surface",
    )
    require_contains(
        ROOT / "recipes/reproos-image/scripts/reproos-network-wait",
        [
            "REPROOS_NETWORK_READY_FILE",
            "REPROOS_BUSYBOX",
            "REPROOS_NETWORK_READY_ATTEMPTS",
            '"offline"',
            "continuing offline",
            "exit 0",
        ],
        "offline-capable DHCP readiness waiter",
    )
    for composition in [
        IMAGE_RECIPE,
        ISO_RECIPE,
        STAGE_ROOTFS_SCRIPT,
        ROOT / "recipes/reproos-image/scripts/configure-installed-root.sh",
    ]:
        require_contains(
            composition,
            ["reproos-sway.conf"],
            "shared installed desktop composition",
        )
    require_contains(
        ROOT / "recipes/reproos-image/scripts/reproos-udhcpc-hook",
        [
            "bound|renew)",
            "route add default",
            "/run/reproos-network-ready",
        ],
        "shared DHCP lease hook",
    )
    for composition in [
        STAGE_ROOTFS_SCRIPT,
        ROOT / "recipes/reproos-image/scripts/configure-installed-root.sh",
    ]:
        require_contains(
            composition,
            [
                "reproos-network.service",
                "multi-user.target.wants/reproos-network.service",
            ],
            "shared DHCP composition",
        )

    require_contains(
        CONTAINER_RECIPE,
        [
            'ReproosIncusProjectionActionId* =',
            'ReproosIncusImageActionId* = "reproosContainer.build_image"',
            "isoPackage.ReproosIsoRootfsActionId",
            "isoPackage.ReproosIsoRootfsOutput",
            'target("incus-projection", projectionAction)',
            'target("incus-image", imageAction)',
            "actionCachePolicy = acfpHybrid",
            "automaticMonitorPolicy(@[projectionOutputAbs])",
            "automaticMonitorPolicy(@[imageBuildDirAbs])",
        ],
        "Incus image graph",
    )
    require_contains(
        ROOT / "recipes/reproos-container/scripts/build-incus-image.sh",
        [
            "metadata.yaml",
            'alias=reproos-incus',
            'generation=$generation',
            'reproos.generation: $generation',
            "reproos_image_metadata.py",
            'SOURCE_DATE_EPOCH="$epoch"',
            "packages/source/kernel",
            "projection-report.json",
        ],
        "deterministic Incus image driver",
    )
    require_contains(
        ROOT / "tools/reproos-incus-publication.py",
        [
            'INDEX_SCHEMA = "org.reproos.incus.index.v1"',
            'PUBLICATION_SCHEMA = "org.reproos.incus.publication.v1"',
            'SIGNATURE_NAMESPACE = "reproos-incus-publication-v1"',
            "def sign_file(",
            "def verify_signature(",
            "immutable generation conflict",
            "downloaded Incus image SHA-256 does not match",
        ],
        "signed Incus publication contract",
    )
    require_contains(
        ROOT / "tools/reproos-incus.sh",
        [
            "--type=bridge",
            "features.networks=false",
            "features.storage.volumes=true",
            "user.reproos.managed=true",
            'user.reproos.project="$project"',
            'storage create "$storage" dir',
            "refusing to modify unowned Incus storage pool",
            "refusing to modify unowned Incus instance",
            'config set "$instance" user.reproos.managed true',
            "refusing to manage the default Incus project",
            "refusing to modify unowned Incus project",
            "environment.REPROOS_INCUS_IPV4",
            'network="$network"',
            'incus_global network delete "$network"',
            "Linux maximum of 15 characters",
            'incus_global project delete "$project"',
        ],
        "isolated Incus bridge and non-interactive cleanup",
    )
    require_contains(
        INCUS_LIFECYCLE_TEST,
        [
            'network="ro-${tag:0:12}"',
            'storage="rs-${tag:0:12}"',
            "default-networks.before",
            "default-networks.after",
            '"$operation" --backend incus "$@"',
            'monitor --type=lifecycle',
            '"$output/address.json"',
            '"$output/generation.txt"',
            '"$output/storage.yaml"',
            "storage-pools.before",
            "storage-pools.after",
            "reproos-generation stage",
            "reproos-generation switch",
            "reproos-generation rollback",
            "/proc/sys/kernel/random/boot_id",
        ],
        "isolated vm-harness lifecycle and failure evidence",
    )
    require_contains(
        ROOT / "tests/test-incus-parallel-isolation.sh",
        [
            "launch_one a &",
            "launch_one b &",
            'storage_for() {',
            'user.reproos.managed',
            '"$vm_harness" instance wait',
            '"$vm_harness" instance exec',
            "ReproOS parallel Incus lifecycle isolation: PASS",
        ],
        "parallel Incus isolation acceptance",
    )
    lifecycle_content = source(INCUS_LIFECYCLE_TEST)
    for direct_operation in ["incus_test exec", "incus_test file"]:
        if direct_operation in lifecycle_content:
            raise AssertionError(
                f"Incus lifecycle bypasses vm-harness: {direct_operation}"
            )
    require_contains(
        ROOT / "tests/test-vm-incus-parity.sh",
        [
            '"$vm_harness" instance exec',
            "--backend incus",
            "bash:/usr/bin/bash",
            "openssh:/usr/sbin/sshd",
            "package.%s.sha256",
            "service.sshd.enabled",
            "multi-user.target.wants/sshd.service",
            "busybox pidof sshd",
            "network.default-route",
            "application.ssh-response",
            "REPROOS_INCUS_HEALTH:PASS",
        ],
        "vm-harness-owned Incus parity probe",
    )
    require_contains(
        ROOT / "recipes/reproos-image/scripts/configure-installed-root.sh",
        [
            'CONFIGURATION_SHA256="$(sha256sum "$CFG"',
            '"$ROOT_TREE/etc/repro/generation"',
        ],
        "installed VM generation identity",
    )
    require_contains(
        ROOT / "tests/test_reproos_incus_helper.py",
        [
            "refusing to manage the default Incus project",
            "refusing to manage reserved Incus bridge",
            "refusing to modify unowned Incus project",
            "refusing to modify unowned Incus network",
            "refusing to modify unowned Incus storage pool",
            "refusing to modify unowned Incus instance",
        ],
        "Incus resource refusal regressions",
    )
    require_contains(
        ROOT / "tests/test-incus-lifecycle.sh",
        [
            "snapshot_unmanaged_resources",
            'resource.get("config", {}).get("user.reproos.project")',
            "assert_baseline_preserved network",
            "assert_baseline_preserved storage",
        ],
        "concurrent Incus baseline preservation",
    )
    require_contains(
        ROOT / "tests/test-incus-image-reproducibility.sh",
        [
            'bash "$builder"',
            'etc_repro.linkname != "/var/lib/reproos/current-generation"',
            'r"generations/[0-9a-f]{64}"',
            '"realization.json"',
        ],
        "portable Incus reproducibility builder invocation",
    )
    require_contains(
        ROOT / "recipes/reproos-container/scripts/project-incus-config.py",
        [
            'class FieldClass(str, Enum)',
            '"incus-system-container"',
            '"invalid-for-incus"',
            '"provider": "host"',
            '"privilege": "unprivileged"',
        ],
        "typed Incus projection",
    )
    require_contains(
        ROOT / "recipes/reproos-container/scripts/project-incus-config.py",
        [
            "REPROOS_INCUS_IPV4",
            "Privilege-separated SSH",
            "current-generation",
            "previous-generation",
            "reproos-generation {current|list|stage|switch|rollback}",
        ],
        "container static-network and SSH runtime",
    )
    require_contains(
        ROOT / "tests/test_incus_projection.py",
        ['assert "UsePAM" not in sshd_config'],
        "container SSH compatibility regression",
    )

    active_sources = [
        ISO_RECIPE,
        IMAGE_RECIPE,
        CONTAINER_RECIPE,
        STAGE_ROOTFS_SCRIPT,
        ROOT / "recipes/reproos-iso/scripts/build-initramfs.sh",
        ROOT / "recipes/reproos-image/scripts/build-reproos-image.sh",
    ]
    for path in active_sources:
        content = source(path)
        for legacy in [
            "$REPO_ROOT/recipes/packages/source",
            "/opt/repro/reprobuild/recipes/packages/source",
        ]:
            if legacy in content:
                raise AssertionError(f"legacy source root remains in {path}: {legacy}")

    stage_path = active_sources[3]
    stage_content = source(stage_path)
    stage_requirements = [
        "stage filesystem is case-insensitive",
        'case_probe_lower_inode="$(stat -c %i "$case_probe_dir/lower")"',
        'ln -sfn "$modprobe_target" "$STAGE_DIR/usr/sbin/modprobe"',
        'ln -sfn "$busybox_target" "$STAGE_DIR/usr/bin/hostname"',
        "required source BusyBox hostname applet missing",
        "usr/lib/x86_64-linux-gnu/security",
        "REPRO_RUNTIME_SOURCE_ROOT:-/opt/repro/reprobuild-packages/packages/source",
        'install -m 0644 "$REPO_ROOT/tests/fixtures/auto-config-minimal.toml"',
        "rewrote $rewritten_source_links build-root source links",
        "required source D-Bus configuration missing",
        "org.freedesktop.login1.service",
        "usr/lib/security/pam_systemd.so",
        "usr/libexec/sddm-helper",
        "auth required pam_permit.so",
        "session include common-session",
        "etc/pam.d/systemd-user",
        "required source graphics runtime data missing",
        "usr/lib/dri/virtio_gpu_dri.so",
        "FONTCONFIG_PATH=/usr/etc/fonts",
        "LIBGL_DRIVERS_PATH=/usr/lib/dri",
        "export QT_QUICK_BACKEND=software",
        "export WLR_RENDERER=pixman",
        'qtpkg_prefix="/opt/repro/reprobuild-packages/packages/source/${repro_qt_pkg}/.repro/output/install/usr"',
        "${qtpkg_prefix}/plugins/platforms",
        "Environment=LANG=C.UTF-8",
        "packages/source/gcc/.repro/output/install/usr/lib64",
        "required source repro runtime library directory missing",
        '--set-rpath "$repro_runtime_rpath" "$STAGE_DIR/usr/bin/repro"',
        '/usr/bin/reproos-installer-launcher.sh "$@"',
        "link_entry sway swaymsg",
        "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        'if [ "$(id -u)" -eq 0 ] && [ "$(tty)" = "/dev/tty1" ]',
        "source glibc C.UTF-8 locale generation failed",
        "--no-archive",
        "usr/lib/locale/C.utf8/LC_CTYPE",
        "usr/lib/locale/C.utf8/LC_MESSAGES/SYS_LC_MESSAGES",
        'I18NPATH="$SOURCE_GLIBC_LOCALEDATA"',
        "release version [0-9]+\\.[0-9]+",
        '"$SOURCE_GLIBC_RUNTIME_DIR_STAGED/libc.so.6"',
        'localedef_runner="$(realpath -m "$STAGE_DIR/tmp/reproos-localedef")"',
        'SOURCE_GLIBC_LOADER_RUNNER="$(realpath -m "$SOURCE_GLIBC_LOADER_STAGED")"',
        'SOURCE_GLIBC_RUNTIME_DIR_RUNNER="$(realpath -m "$SOURCE_GLIBC_RUNTIME_DIR_STAGED")"',
        '"$patchelf_bin" --force-rpath',
        '"$localedef_runner"',
        'SOURCE_RUNTIME_REPRO_BIN="${REPRO_CLI_BIN:-${REPROBUILD_SRC:-$REPO_ROOT/../reprobuild}/build/bin/repro}"',
        '"$ISO_SRC_MIRROR_ROOT" --check "/sbin/ldconfig" --executable',
        'ldconfig_runner="$(realpath -m "$STAGE_DIR/tmp/reproos-ldconfig")"',
        "source ldconfig must be dynamically linked for observable cache generation",
        '"$ldconfig_runner" -r "$STAGE_DIR"',
        '"$STAGE_DIR$SOURCE_GLIBC_LOADER"',
        '"$SOURCE_GLIBC_VERSION"',
        '--audit-source-links --build-source-root "$SRC_RECIPES_ROOT"',
    ]
    for value in stage_requirements:
        if value not in stage_content:
            raise AssertionError(f"ISO staging is missing runtime surface: {value}")
    for obsolete_invocation in [
        '"$busybox_src" --list',
        '"$SOURCE_GLIBC_LOADER_STAGED" --version',
        '"$SRC_RECIPES_ROOT/glibc/src/version.h"',
        '"$SRC_RECIPES_ROOT/glibc/src/localedata"',
    ]:
        if obsolete_invocation in stage_content:
            raise AssertionError(
                "ISO staging executes an image-owned validation helper: "
                f"{obsolete_invocation}"
            )

    for package in ["pam", "kbd", "openssh"]:
        if re.search(
            rf"BASE_USERSPACE_RECIPES=\(.*?^  {re.escape(package)}$.*?^\)",
            stage_content,
            flags=re.MULTILINE | re.DOTALL,
        ) is None:
            raise AssertionError(f"source {package} is not in base userspace staging")
    for package in ["clingo", "qt6-wayland"]:
        if package not in iso_dependencies:
            raise AssertionError(f"source {package} is not in the bootable package closure")
    if "required source loadkeys binary missing" not in stage_content:
        raise AssertionError("source kbd runtime validation is missing")
    for value in [
        "required source OpenSSH runtime missing",
        "reproos-network.service",
        "ExecStartPre=/usr/bin/ssh-keygen -A",
        "ExecStart=/usr/sbin/sshd -D -e",
    ]:
        if value not in stage_content and value not in image_script:
            raise AssertionError(
                f"installed SSH acceptance surface is missing: {value}"
            )

    require_contains(
        NORMALIZE_RUNTIME_SCRIPT,
        [
            "SOURCE_GLIBC_VERSION [EXTRA_ELF ...]",
            'source_glibc_version="$4"',
            "stage_path_is_executable",
            'provider_indexer="$script_dir/source-runtime-providers.py"',
            '--check "$1" --executable',
            '"${source_provider_error[$needed]:-}"',
            'if ! stage_path_is_executable "$target"',
            'run_patchelf_mutation "$elf" set-interpreter',
            '[ "$old_interpreter" != "$source_glibc_loader" ]',
            "patchelf failed for ${elf#$stage_dir}",
        ],
        "source runtime normalization",
    )
    if '"$source_glibc_loader_staged" --version' in source(
        NORMALIZE_RUNTIME_SCRIPT
    ):
        raise AssertionError("runtime normalization executes the image-owned loader")
    base_rootfs_content = source(
        ROOT / "recipes/reproos-iso/scripts/build-base-rootfs.sh"
    )
    if re.search(r"(^|\s)chown\s", base_rootfs_content):
        raise AssertionError("base rootfs staging must remain unprivileged")
    for ownership_flag in ["--numeric-owner", "--owner=0", "--group=0"]:
        if ownership_flag not in base_rootfs_content:
            raise AssertionError(
                f"base rootfs staging is missing deterministic ownership: {ownership_flag}"
            )
    require_contains(
        ROOT / "recipes/reproos-iso/scripts/build-iso.sh",
        ["reproos_image_metadata.py", "-all-root -root-mode 0755", "-pseudo-override", "-no-hardlinks"],
        "SquashFS staging",
    )
    # The raw-ext4 carrier of the SAME policy. `mkfs.ext4 -d` copies the
    # unprivileged staging tree's ownership, so without these two steps the
    # integrity-checked root ships /etc/shadow owned by the building user
    # and /usr/bin/sudo with no setuid bit -- and the root hash covers that.
    # The verify is not decoration: it is what stops an image reaching the
    # hash without the policy in it.
    verity_root_content = source(ROOT / "recipes/reproos-image/scripts/build-verity-root.sh")
    for step in ["ext4-apply", "ext4-verify"]:
        if not re.search(
            r'^\s*(if\s+!\s+)?python3\s+"\$INODE_POLICY"\s+' + step,
            verity_root_content,
            re.MULTILINE,
        ):
            raise AssertionError(
                f"the integrity-checked root builder never RUNS the guest inode policy: {step}"
            )
    if verity_root_content.index("ext4-verify") > verity_root_content.index("veritysetup format"):
        raise AssertionError(
            "the integrity-checked root builder takes its root hash before it "
            "checks that the guest inode policy is in the image"
        )
    require_contains(
        ROOT / "apps/reproos-installer/qml/main.qml",
        ['import "components"', "color: Theme.canvas", 'id: "deSelect"', 'id: "finished"'],
        "installer chrome",
    )

    desktop_content = source(ROOT / "apps/reproos-installer/qml/screens/DeSelect.qml")
    if 'title: "Sway"' not in desktop_content:
        raise AssertionError("installer does not expose the source-built Sway desktop")
    for desktop in ["KDE Plasma", "GNOME", "Hyprland"]:
        if desktop in desktop_content:
            raise AssertionError(f"installer advertises unavailable desktop: {desktop}")

    require_contains(
        ROOT / "apps/reproos-installer/qml/screens/Activities.qml",
        ["installerState.activeActivities = []"],
        "installer activity screen",
    )

    require_attestation_agent_installed()

    require_nim_gate_declarations()

    print(f"Validated {len(iso_dependencies)} source packages in both bootable targets.")


if __name__ == "__main__":
    main()
