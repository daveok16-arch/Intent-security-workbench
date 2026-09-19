#!/usr/bin/env bash
#
# Provision the external analysis binaries the workbench engines invoke.
#
# The engines report NOT_INSTALLED truthfully when a tool is absent, so the app
# runs without this script — it simply cannot execute those engines. This script
# installs them so the platform is actually productive.
#
# Idempotent: re-running skips anything already present.
# Verify-only mode: ./scripts/setup-tools.sh --check

set -uo pipefail

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[0;33m'; DIM=$'\033[2m'; NC=$'\033[0m'

ok()   { printf "%s  ok  %s%s\n" "$GREEN" "$1" "$NC"; }
miss() { printf "%s miss %s%s\n" "$RED" "$1" "$NC"; }
skip() { printf "%s skip %s%s\n" "$YELLOW" "$1" "$NC"; }
note() { printf "%s      %s%s\n" "$DIM" "$1" "$NC"; }

FAILED=0

have() { command -v "$1" >/dev/null 2>&1; }

# pip installs to the user site; ensure that directory is on PATH for this shell
# and for the server.
export PATH="$HOME/.local/bin:$HOME/.foundry/bin:$PATH"

require_pip() {
  if have pip3; then echo pip3; elif have pip; then echo pip; else echo ""; fi
}

install_python_tool() {
  local bin="$1" pkg="$2"
  if have "$bin"; then
    ok "$bin ($($bin --version 2>&1 | head -1))"
    return 0
  fi
  if [[ $CHECK_ONLY -eq 1 ]]; then miss "$bin not installed"; FAILED=1; return 1; fi
  local pip; pip="$(require_pip)"
  if [[ -z "$pip" ]]; then skip "$bin (no pip available)"; FAILED=1; return 1; fi
  note "installing $pkg ..."
  if "$pip" install --quiet --user "$pkg" >/tmp/tool_install_$$.log 2>&1; then
    if have "$bin"; then ok "$bin ($($bin --version 2>&1 | head -1))"; return 0; fi
    skip "$bin installed but not on PATH"; FAILED=1; return 1
  fi
  skip "$bin install failed (see /tmp/tool_install_$$.log)"; FAILED=1; return 1
}

printf "\n%s\n" "=============================================="
printf " Intent Security Workbench - toolchain setup\n"
[[ $CHECK_ONLY -eq 1 ]] && printf " (verify only)\n"
printf "%s\n\n" "=============================================="

# --- Required for core functionality -----------------------------------------
if have git; then ok "git ($(git --version))"; else miss "git is required"; FAILED=1; fi

install_python_tool semgrep semgrep

if have z3; then
  zv="$(z3 --version 2>&1 | head -1)"
  if [[ "$zv" =~ 4\.[0-9]+\.[0-9]+ ]]; then ok "z3 ($zv)"; else skip "z3 version unexpected: $zv"; FAILED=1; fi
else
  if [[ $CHECK_ONLY -eq 1 ]]; then miss "z3 not installed"; FAILED=1; else
    pip="$(require_pip)"
    if [[ -n "$pip" ]]; then
      note "installing z3-solver==4.13.0.0 ..."
      if "$pip" install --quiet --user "z3-solver==4.13.0.0" >/tmp/z3_install_$$.log 2>&1 && have z3; then
        ok "z3 ($(z3 --version 2>&1 | head -1))"
      else
        skip "z3 install failed"; FAILED=1
      fi
    else skip "z3 (no pip available)"; FAILED=1; fi
  fi
fi

if have forge; then ok "forge ($(forge --version 2>&1 | head -1))"
else
  if [[ $CHECK_ONLY -eq 1 ]]; then miss "forge not installed"; FAILED=1; else
    if have foundryup; then
      note "running foundryup ..."
      foundryup >/tmp/foundryup_$$.log 2>&1 || true
      if have forge; then ok "forge ($(forge --version 2>&1 | head -1))"; else skip "forge install failed"; FAILED=1; fi
    else
      skip "forge (foundryup not found; run: curl -L https://foundry.paradigm.xyz | bash)"
    fi
  fi
fi

# --- Optional engines ---------------------------------------------------------
install_python_tool slither slither-analyzer || true

# angr must stay pinned at 9.2.160. angr 10.x pins z3-solver==5.1.0.0, which
# replaces the 4.x that tests/unit/formal_verification.test.ts asserts, so an
# unpinned install here silently breaks the Z3 suite *after* the z3 check above
# has already passed. 9.2.160 pins z3-solver==4.13.0.0 and needs pycparser==2.22
# (3.x breaks angr.sim_type).
if have python3 && python3 -c "import angr" >/dev/null 2>&1; then
  angr_v="$(python3 -c 'import angr; print(angr.__version__)' 2>/dev/null || echo unknown)"
  if [[ "$angr_v" == 9.2.160 ]]; then
    ok "angr ($angr_v)"
  else
    skip "angr $angr_v is not the pinned 9.2.160 (run: pip install 'angr==9.2.160' 'pycparser==2.22')"
    FAILED=1
  fi
else
  install_python_tool angr "angr==9.2.160" || true
fi
# pycparser is pinned alongside angr; keep it aligned.
if [[ $CHECK_ONLY -eq 0 ]] && have python3 && python3 -c "import angr" >/dev/null 2>&1; then
  pip="$(require_pip)"
  [[ -n "$pip" ]] && "$pip" install --quiet --user "pycparser==2.22" >/dev/null 2>&1 || true
fi

if have spectral || [[ -x node_modules/.bin/spectral ]]; then ok "spectral (project dependency)"
else skip "spectral (run: npm install)"; fi

printf "\n"
if [[ $FAILED -eq 0 ]]; then
  printf "%sAll required tools present.%s\n\n" "$GREEN" "$NC"
  printf "Run 'npm test' to verify the engines detect them (221 tests).\n\n"
  exit 0
else
  printf "%sSome tools are missing.%s The workbench will still run and will report\n" "$YELLOW" "$NC"
  printf "those engines as NOT_INSTALLED rather than fabricating results.\n\n"
  exit 1
fi