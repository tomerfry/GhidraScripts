#!/usr/bin/env python3
"""
TG_joern_integration.py

Exports decompiled code from Ghidra, builds a Joern CPG, and launches Joern with the CPG loaded.

Requirements:
  - Run from Ghidra Script Manager (Python3-capable environment)
  - Joern installed (JOERN_HOME env var OR joern/joern-parse in PATH)

Notes:
  - On Windows, Joern sometimes fails if a backslash path is injected into Scala code.
    This script forces forward slashes when constructing importCpg(...) statements.
"""

import os
import subprocess
import shutil
import hashlib
import time
from pathlib import Path
from dataclasses import dataclass

# --- Ghidra imports ---
try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False


# -----------------------------
# Models / helpers
# -----------------------------
@dataclass
class DecompilationResult:
    name: str
    address: str
    code: str


def _safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in s)


def _hash_file(path: Path, algo: str = "md5", chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def get_persistent_workspace(program_name: str, program_hash: str) -> Path:
    base_dir = Path.home() / ".ghidra_joern"
    base_dir.mkdir(parents=True, exist_ok=True)

    folder_name = f"{_safe_name(program_name)}_{program_hash[:8]}"
    ws = base_dir / folder_name
    ws.mkdir(parents=True, exist_ok=True)
    return ws


def _to_posix_path(p: Path) -> str:
    # Important for Scala/Windows: forward slashes avoid \U, \. etc.
    return str(p).replace("\\", "/")


# -----------------------------
# Joern user scripts configuration
# -----------------------------

# Folder where you keep your custom Joern scripts.
# You can override it with an environment variable:
#   setx JOERN_SCRIPTS_DIR "C:\path\to\joern-scripts"
JOERN_SCRIPTS_DIR = Path(os.environ.get(
    "JOERN_SCRIPTS_DIR",
    r"C:\Users\User\Desktop\Profession\GhidraScripts\joern-scripts"
))


# Which scripts to auto-import on startup (comma-separated).
# Override with:
#   setx JOERN_AUTO_IMPORT "uaf_heuristic.sc"
JOERN_AUTO_IMPORT = [
    s.strip() for s in os.environ.get("JOERN_AUTO_IMPORT", "uaf_heuristic.sc,primitives.sc,memcorr_primitives.sc,info_leak.sc").split(",")
    if s.strip()
]


def build_joern_predef(workspace: Path, scripts_dir: Path, scripts: list[str]) -> Path:
    """
    Create a predef script that imports your custom scripts via scala-cli directives.
    Joern's --import compiles these and makes their objects available in the REPL.
    """
    predef = workspace / "joern_predef.sc"
    lines = []

    if not scripts_dir.exists():
        print(f"[!] JOERN_SCRIPTS_DIR does not exist: {scripts_dir}")
    else:
        for name in scripts:
            p = (scripts_dir / name).resolve()
            if p.exists():
                # Use forward slashes so Joern/Scala won't trip over backslashes
                lines.append(f"//> using file {_to_posix_path(p)}")
            else:
                print(f"[!] Script not found: {p}")

    predef.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return predef


# -----------------------------
# Ghidra exporter
# -----------------------------
class GhidraExporter:
    def __init__(self, program):
        self.program = program
        self.decomp = DecompInterface()
        self.decomp.openProgram(program)
        self.monitor = ConsoleTaskMonitor()

    def get_program_hash(self) -> str:
        """
        Prefer hashing the executable file if the path exists.
        Fallback to hashing stable program metadata.
        """
        try:
            exe_path = self.program.getExecutablePath()
            if exe_path:
                p = Path(str(exe_path))
                if p.exists() and p.is_file():
                    return _hash_file(p, "md5")
        except Exception:
            pass

        info = f"{self.program.getName()}|{self.program.getCreationDate()}|{self.program.getLanguage()}"
        return hashlib.md5(info.encode("utf-8", errors="ignore")).hexdigest()

    def decompile_function(self, func, timeout=60):
        results = self.decomp.decompileFunction(func, timeout, self.monitor)
        if not results or not results.decompileCompleted():
            return None

        decomp_func = results.getDecompiledFunction()
        if not decomp_func:
            return None

        return DecompilationResult(
            name=func.getName(),
            address=str(func.getEntryPoint()),
            code=decomp_func.getC()
        )

    def export_to_directory(self, output_dir: Path) -> Path:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        consolidated = output_dir / "decompiled.c"
        func_manager = self.program.getFunctionManager()
        exported = 0

        with consolidated.open("w", encoding="utf-8", errors="ignore") as f:
            f.write("// Auto-generated by TG_joern_integration.py\n")
            f.write(f"// Source: {self.program.getName()}\n\n")
            f.write("#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n\n")

            # Ghidra-ish typedefs that frequently appear in decompiler output
            f.write("typedef uint8_t  undefined;\n")
            f.write("typedef uint8_t  undefined1;\n")
            f.write("typedef uint16_t undefined2;\n")
            f.write("typedef uint32_t undefined4;\n")
            f.write("typedef uint64_t undefined8;\n")
            f.write("typedef uint8_t  byte;\n")
            f.write("typedef uint16_t word;\n")
            f.write("typedef uint32_t dword;\n")
            f.write("typedef uint64_t qword;\n")
            f.write("typedef unsigned char  uchar;\n")
            f.write("typedef unsigned short ushort;\n")
            f.write("typedef unsigned int   uint;\n")
            f.write("typedef unsigned long  ulong;\n\n")

            for func in func_manager.getFunctions(True):
                if self.monitor.isCancelled():
                    break
                if func.isExternal() or func.isThunk():
                    continue

                res = self.decompile_function(func)
                if not res:
                    continue

                f.write(f"\n// === {res.name} @ {res.address} ===\n")
                f.write(res.code)
                f.write("\n")

                exported += 1
                if exported % 50 == 0:
                    print(f"[*] Exported {exported} functions...")

        print(f"[+] Exported {exported} functions to {consolidated}")
        return consolidated

    def close(self):
        try:
            self.decomp.dispose()
        except Exception:
            pass


# -----------------------------
# Joern interface
# -----------------------------
class JoernInterface:
    COMMON_PATHS = [
        r"C:\joern", r"C:\Program Files\joern", r"C:\tools\joern",
        os.path.expanduser(r"~\joern"), os.path.expanduser(r"~\tools\joern"),
        os.path.expanduser(r"~\joern-cli"), os.path.expanduser(r"~\Desktop\Profession\joern-cli"),
        "/opt/joern", "/usr/local/joern", os.path.expanduser("~/joern"),
    ]

    def __init__(self, joern_home=None):
        self.joern_home = joern_home or os.environ.get("JOERN_HOME")
        self.joern_bin = None
        self.joern_parse = None

        if not self._find_joern():
            raise RuntimeError("Joern not found. Set JOERN_HOME or add joern/joern-parse to PATH.")

    def _find_binary(self, name: str, search_dir=None):
        is_windows = (os.name == "nt")
        exts = [".bat", ".cmd", ".exe", ""] if is_windows else [""]

        if search_dir is None:
            for ext in exts:
                p = shutil.which(name + ext)
                if p:
                    return p
            return None

        search_dir = Path(search_dir)
        subdirs = ["bin", "joern-cli", "joern-cli/bin", ""]

        for sub in subdirs:
            base = search_dir / sub if sub else search_dir
            for ext in exts:
                cand = base / (name + ext)
                if cand.exists():
                    return str(cand)
        return None

    def _find_joern(self) -> bool:
        if self.joern_home:
            self.joern_bin = self._find_binary("joern", self.joern_home)
            self.joern_parse = self._find_binary("joern-parse", self.joern_home)
            if self.joern_bin:
                return True

        self.joern_bin = self._find_binary("joern")
        self.joern_parse = self._find_binary("joern-parse")
        if self.joern_bin:
            return True

        for path in self.COMMON_PATHS:
            if os.path.isdir(path):
                jb = self._find_binary("joern", path)
                if jb:
                    self.joern_home = path
                    self.joern_bin = jb
                    self.joern_parse = self._find_binary("joern-parse", path)
                    print(f"[+] Found Joern at: {path}")
                    return True

        return False

    def create_cpg(self, source_file: Path, output_path: Path) -> Path:
        """
        Build a CPG from a single source file (decompiled.c).
        """
        source_file = Path(source_file)
        output_path = Path(output_path)

        print(f"[*] Generating CPG from {source_file}...")
        is_windows = (os.name == "nt")

        if not self.joern_parse:
            raise RuntimeError("joern-parse not found. Install full Joern distribution or ensure joern-parse is in PATH.")

        # Use argv list (avoid shell quoting problems)
        cmd = [self.joern_parse, str(source_file), "-o", str(output_path), "--language", "c"]

        # If joern-parse is .bat/.cmd, Windows needs shell=True to run it
        use_shell = is_windows and str(self.joern_parse).lower().endswith((".bat", ".cmd"))

        result = subprocess.run(cmd, capture_output=True, text=True, shell=use_shell)

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            msg = stderr or stdout or f"joern-parse failed with code {result.returncode}"
            raise RuntimeError(msg)

        print(f"[+] CPG saved to {output_path}")
        return output_path


# -----------------------------
# Joern launcher
# -----------------------------
def launch_joern_terminal(joern_bin: str, cpg_path: Path, program_name: str, predef: Path | None = None):
    """
    Launch Joern with the CPG loaded using --runBefore 'importCpg("...")'
    and optionally auto-import custom scripts via --import predef.sc.
    """
    cpg_posix = _to_posix_path(Path(cpg_path))
    scala_stmt = f'importCpg("{cpg_posix}")'

    is_windows = (os.name == "nt")
    jb = str(joern_bin)

    print("")
    print("=" * 60)
    print(f"Launching Joern with CPG: {program_name}")
    print("=" * 60)
    print("")

    # Build common argv
    argv = [jb]
    if predef is not None and Path(predef).exists():
        argv += ["--import", str(predef)]
    argv += ["--runBefore", scala_stmt]

    if is_windows:
        lower = jb.lower()
        if lower.endswith((".bat", ".cmd")):
            # Need cmd.exe quoting; also keep Scala statement safe
            run_before = f'importCpg(""{cpg_posix}"")'

            import_part = ""
            if predef is not None and Path(predef).exists():
                import_part = f' --import "{predef}"'

            title = f"Joern - {program_name}"
            cmd = f'start "{title}" cmd /k ""{jb}"{import_part} --runBefore "{run_before}""'
            subprocess.Popen(cmd, shell=True)
        else:
            # Native exe: pass argv list, avoid quoting issues
            try:
                CREATE_NEW_CONSOLE = subprocess.CREATE_NEW_CONSOLE  # type: ignore[attr-defined]
                subprocess.Popen(argv, creationflags=CREATE_NEW_CONSOLE)
            except Exception:
                subprocess.Popen(argv)

        print("[+] Joern launched")
        return

    # Linux/macOS: direct run (or wrap in terminal if you want)
    subprocess.Popen(argv)
    print("[+] Joern launched")


# -----------------------------
# Main
# -----------------------------
def main():
    if not GHIDRA_AVAILABLE:
        print("[!] Run this script from Ghidra Script Manager")
        return 1

    exporter = None
    try:
        current_program = getCurrentProgram()  # noqa: F821
        if current_program is None:
            print("[!] No program loaded in Ghidra")
            return 1

        program_name = current_program.getName()
        print(f"[+] Program: {program_name}")
        print(f"[+] Arch: {current_program.getLanguage().getProcessor()}")

        exporter = GhidraExporter(current_program)
        program_hash = exporter.get_program_hash()

        workspace = get_persistent_workspace(program_name, program_hash)
        print(f"[+] Workspace: {workspace}")

        safe = _safe_name(program_name)
        cpg_path = workspace / f"{safe}.cpg.bin"
        decompiled_path = workspace / "decompiled.c"

        # Reuse if both exist
        if cpg_path.exists() and decompiled_path.exists():
            print("[*] Using existing CPG (delete workspace to regenerate)")
        else:
            decompiled_file = exporter.export_to_directory(workspace)
            joern = JoernInterface()
            joern.create_cpg(decompiled_file, cpg_path)

        # Launch Joern
        # Build predef that auto-loads your custom scripts
        predef = build_joern_predef(workspace, JOERN_SCRIPTS_DIR, JOERN_AUTO_IMPORT)

        # Launch Joern with CPG + your predef imports
        joern = JoernInterface()
        launch_joern_terminal(joern.joern_bin, cpg_path, program_name, predef=predef)
        print(f"\n[*] Workspace: {workspace}")
        return 0

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if exporter is not None:
            exporter.close()


if __name__ == "__main__":
    main()
