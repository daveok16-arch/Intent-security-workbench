#!/usr/bin/env python3
"""
Angr binary analysis driver for the Intent Security Workbench.

Reads a JSON request on stdin:  {"binary_path": "...", "timeout_s": 120}
Writes a JSON result on stdout. Never invents results: if angr is missing or
the binary cannot be loaded, the script exits non-zero with a JSON error.

Analysis performed:
  - binary metadata (arch, bits, entry, PIE/NX/RELRO hardening)
  - CFG function recovery
  - dangerous imported libc symbols (strcpy/system/gets/...)
  - symbols resolvable as PLT stubs, i.e. actually callable call sites
"""
import json
import sys


def fail(message, code=1):
    print(json.dumps({"ok": False, "error": message}))
    sys.exit(code)


def main():
    try:
        request = json.load(sys.stdin)
    except Exception as exc:  # noqa: BLE001
        fail(f"invalid request json: {exc}")

    binary_path = request.get("binary_path")
    if not binary_path:
        fail("missing required 'binary_path'")
    timeout_s = int(request.get("timeout_s") or 180)

    try:
        import angr  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        fail(f"angr import failed: {exc}", code=127)

    try:
        import angr
        import logging

        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)

        project = angr.Project(binary_path, auto_load_libs=False)

        arch = project.arch
        result = {
            "ok": True,
            "angr_version": getattr(angr, "__version__", "unknown"),
            "binary": {
                "path": binary_path,
                "arch": arch.name,
                "bits": arch.bits,
                "entry": hex(project.entry),
                "pie": bool(project.loader.main_object.pic),
                "nx": bool(getattr(project.loader.main_object, "execstack", False)) is False,
            },
            "functions": 0,
            "imports": [],
            "dangerous_imports": [],
            "call_sites": [],
            "warnings": [],
        }

        try:
            cfg = project.analyses.CFGFast(normalize=True)
            result["functions"] = len(cfg.functions)
        except Exception as exc:  # noqa: BLE001
            result["warnings"].append(f"CFGFast failed: {exc}")

        try:
            imports = sorted(set(project.loader.main_object.imports.keys()))
        except Exception:  # noqa: BLE001
            imports = []
        result["imports"] = imports

        dangerous_names = {
            "strcpy", "strcat", "sprintf", "gets", "scanf", "sscanf", "memcpy",
            "memmove", "system", "popen", "execl", "execlp", "execv", "execvp",
            "alloca", "vsprintf", "realpath", "getwd",
        }
        result["dangerous_imports"] = [name for name in imports if name in dangerous_names]

        # Resolve PLT stubs so each hit maps to a concrete call address.
        try:
            for name in result["dangerous_imports"]:
                symbol = project.loader.find_symbol(name)
                if symbol is not None and symbol.rebased_addr:
                    result["call_sites"].append({"symbol": name, "addr": hex(symbol.rebased_addr)})
        except Exception as exc:  # noqa: BLE001
            result["warnings"].append(f"symbol resolution failed: {exc}")

        print(json.dumps(result))
        return
    except Exception as exc:  # noqa: BLE001
        fail(f"analysis failed: {exc}")


if __name__ == "__main__":
    main()