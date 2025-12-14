# TG_memcorr_step1d_bounded_copy_stack_overflow.py
# TG MemCorr Detector - Step 1d
# Focus: stack buffer overflow candidates from bounded copy APIs (memcpy/memmove/strncpy/strncat)
# Includes fortify _chk variants (__memcpy_chk, __strncpy_chk, etc.)
# Also supports interactive tagging of unknown externals for portability across binaries.
#
# @category Security
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import CodeUnit
from collections import Counter
import json, os

# -----------------------------
# Config
# -----------------------------
CONFIG = {
    "decompile_timeout_s": 60,
    "max_funcs": None,  # None => all
    "max_expr_depth": 24,
    "emit_bookmarks": True,
    "emit_comments": True,

    # Heuristics
    "flag_const_minus_var_size": True,     # e.g., 0x80 - uVar4
    "flag_var_minus_const_size": True,     # e.g., uVar4 - 0x80
    "emit_low_confidence": True,           # also record candidates where len is not constant
    "interactive_external_tagging": True,  # prompt to tag unknown externals

    # Output
    "print_top_calls": 40,
}

# -----------------------------
# Default external database
# Researchers can extend via overrides json.
# "DST_ARG", "LEN_ARG" are 0-based indices in the C signature.
# For *_chk fortified variants, an extra "OBJLEN_ARG" (destination object size) exists.
# -----------------------------
DEFAULT_EXTERNALS = {
    # bounded copy/move
    "memcpy":      {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2}},
    "memmove":     {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2}},
    "bcopy":       {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 1, "LEN_ARG": 2}},  # bcopy(src,dst,len)

    "strncpy":     {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2}},
    "strncat":     {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2}},

    # fortify variants (glibc / gcc builtins)
    "__memcpy_chk":    {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "__memmove_chk":   {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "__strncpy_chk":   {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "__strncat_chk":   {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "__memset_chk":    {"traits": ["BOUNDED_SET_SINK"],  "params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},  # memset(dst, c, n, objsz)

    # Allow normalized short forms used by our earlier scripts
    "memcpy_chk":      {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "memmove_chk":     {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "strncpy_chk":     {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "strncat_chk":     {"traits": ["BOUNDED_COPY_SINK"], "params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "memset_chk":      {"traits": ["BOUNDED_SET_SINK"],  "params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
}

ALIASES = {
    # Common import naming / fortify aliases
    "__builtin___memcpy_chk": "__memcpy_chk",
    "__builtin___memmove_chk": "__memmove_chk",
    "__builtin___strncpy_chk": "__strncpy_chk",
    "__builtin___strncat_chk": "__strncat_chk",
    "__builtin___memset_chk": "__memset_chk",
}

def normalize_func_name(name):
    if not name:
        return None
    n = name

    # PTR_* import pointer patterns
    if n.startswith("PTR_"):
        rest = n[4:]
        parts = rest.rsplit("_", 1)
        if parts and parts[0]:
            n = parts[0]

    # Strip prefixes
    for pfx in ("imp.", "thunk_", "__imp_", "plt_", "j_"):
        if n.startswith(pfx):
            n = n[len(pfx):]

    # Version / plt suffixes
    if "@@" in n:
        n = n.split("@@")[0]
    if "@plt" in n:
        n = n.replace("@plt", "")
    if n.endswith(".plt"):
        n = n[:-4]

    # Leading underscores except for __* names we actually want to keep
    # We'll normalize by stripping one underscore, but preserve double underscore functions.
    if n.startswith("_") and not n.startswith("__"):
        n = n.lstrip("_")

    # Apply alias map
    n = ALIASES.get(n, n)

    # Also accept *_chk shorthand by stripping a single leading underscore and leaving _chk
    n = n.replace("_chk", "_chk")

    return n

def called_name_from_instruction(callsite_addr):
    """
    Very reliable for direct calls: instruction.getFlows()[0] gives destination.
    Returns None for indirect calls.
    """
    try:
        ins = currentProgram.getListing().getInstructionAt(callsite_addr)
        if not ins:
            return None
        flows = ins.getFlows()
        if not flows:
            return None
        dst = flows[0]
        if not dst:
            return None
        fm = currentProgram.getFunctionManager()
        f = fm.getFunctionAt(dst)
        if f:
            return f.getName()
        sym = currentProgram.getSymbolTable().getPrimarySymbol(dst)
        return sym.getName() if sym else None
    except Exception:
        return None

def is_stack_storage(symbol):
    try:
        st = symbol.getStorage()
        return st and st.isStackStorage()
    except Exception:
        return False

def peel_ptr_expr(vn, max_depth=24):
    """
    Reduce pointer expressions; return (base_vn, accumulated_offset_bytes)
    Handles COPY/CAST/SUBPIECE, PTRSUB, PTRADD, INT_ADD, INT_SUB.
    """
    off = 0
    cur = vn
    depth = 0
    while cur is not None and depth < max_depth:
        depth += 1
        d = cur.getDef()
        if d is None:
            break
        opc = d.getOpcode()

        if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.SUBPIECE, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            cur = d.getInput(0); continue

        if opc == PcodeOp.PTRSUB:
            k = d.getInput(1)
            if k and k.isConstant():
                off += int(k.getOffset())
            cur = d.getInput(0); continue

        if opc == PcodeOp.PTRADD:
            idx = d.getInput(1)
            esz = d.getInput(2) if d.getNumInputs() > 2 else None
            if idx and idx.isConstant():
                delta = int(idx.getOffset())
                if esz and esz.isConstant():
                    delta *= int(esz.getOffset())
                off += delta
            cur = d.getInput(0); continue

        if opc == PcodeOp.INT_ADD:
            rhs = d.getInput(1)
            if rhs and rhs.isConstant():
                off += int(rhs.getOffset())
            cur = d.getInput(0); continue

        if opc == PcodeOp.INT_SUB:
            rhs = d.getInput(1)
            if rhs and rhs.isConstant():
                off -= int(rhs.getOffset())
            cur = d.getInput(0); continue

        break

    return cur, off

def stack_buf_from_ptr(vn, hf):
    """
    Returns (stack_sym_name, stack_total_size, ptr_offset_into_buffer)
    or None if not stack-based.
    """
    if vn is None or hf is None:
        return None

    base, add_off = peel_ptr_expr(vn, CONFIG["max_expr_depth"])

    # 1) HighVariable symbol path (best)
    try:
        high = base.getHigh() if base else None
        if high:
            sym = high.getSymbol()
            if sym and is_stack_storage(sym):
                dt = None
                try:
                    dt = high.getDataType()
                except Exception:
                    pass
                size = None
                try:
                    size = dt.getLength() if dt else sym.getSize()
                except Exception:
                    size = sym.getSize()
                return (sym.getName(), int(size) if size is not None else None, int(add_off))
    except Exception:
        pass

    # 2) Stack-space address varnode fallback (rare in decompiler output but cheap)
    try:
        if base and base.isAddress():
            a = base.getAddress()
            if a and a.getAddressSpace().isStackSpace():
                stack_off = int(a.getOffset()) + int(add_off)
                # Match to local symbol storage
                lsm = hf.getLocalSymbolMap()
                if lsm:
                    for sym in lsm.getSymbols():
                        if not is_stack_storage(sym):
                            continue
                        st = sym.getStorage()
                        try:
                            min_off = None
                            max_off = None
                            for v in st.getVarnodes():
                                if v.getAddress().getAddressSpace().isStackSpace():
                                    o = int(v.getAddress().getOffset())
                                    sz = int(v.getSize())
                                    min_off = o if min_off is None else min(min_off, o)
                                    max_off = o + sz if max_off is None else max(max_off, o + sz)
                            if min_off is not None and max_off is not None and min_off <= stack_off < max_off:
                                return (sym.getName(), int(sym.getSize()), int(stack_off - min_off))
                        except Exception:
                            continue
    except Exception:
        pass

    # 3) UNIQUE varnode defined by PTRSUB(stack_reg, const) (very common)
    try:
        if base:
            d = base.getDef()
            if d and d.getOpcode() == PcodeOp.PTRSUB:
                base2 = d.getInput(0)
                k = d.getInput(1)
                if base2 and base2.isRegister() and k and k.isConstant():
                    # This often represents &local; try to map by absolute stack offset const
                    abs_off = int(k.getOffset()) + int(add_off)
                    lsm = hf.getLocalSymbolMap()
                    if lsm:
                        for sym in lsm.getSymbols():
                            if not is_stack_storage(sym):
                                continue
                            st = sym.getStorage()
                            try:
                                min_off = None
                                max_off = None
                                for v in st.getVarnodes():
                                    if v.getAddress().getAddressSpace().isStackSpace():
                                        o = int(v.getAddress().getOffset())
                                        sz = int(v.getSize())
                                        min_off = o if min_off is None else min(min_off, o)
                                        max_off = o + sz if max_off is None else max(max_off, o + sz)
                                if min_off is not None and max_off is not None and min_off <= abs_off < max_off:
                                    return (sym.getName(), int(sym.getSize()), int(abs_off - min_off))
                            except Exception:
                                continue
    except Exception:
        pass

    return None

def try_parse_const_minus_var(expr_vn, max_depth=20):
    """
    Identify forms: CONST - VAR  or VAR - CONST
    Returns dict like:
      {"kind":"CONST_MINUS_VAR","const":0x80,"var":"uVar4"}
    or None.
    """
    if expr_vn is None:
        return None

    def vname(v):
        try:
            h = v.getHigh()
            if h and h.getSymbol():
                return h.getSymbol().getName()
        except Exception:
            pass
        return "?"

    # Dive through casts/copies
    cur = expr_vn
    depth = 0
    while cur is not None and depth < max_depth:
        depth += 1
        if cur.isConstant():
            return None
        d = cur.getDef()
        if d is None:
            return None
        opc = d.getOpcode()
        if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.SUBPIECE, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            cur = d.getInput(0)
            continue
        if opc == PcodeOp.INT_SUB:
            a = d.getInput(0)
            b = d.getInput(1)
            if a and a.isConstant() and b and not b.isConstant():
                return {"kind":"CONST_MINUS_VAR", "const": int(a.getOffset()), "var": vname(b)}
            if b and b.isConstant() and a and not a.isConstant():
                return {"kind":"VAR_MINUS_CONST", "const": int(b.getOffset()), "var": vname(a)}
            return None
        return None
    return None

def eval_const_int(vn, max_depth=16):
    """
    Basic constant fold for common expressions.
    """
    if vn is None:
        return None
    if vn.isConstant():
        return int(vn.getOffset())

    cur = vn
    depth = 0
    while cur is not None and depth < max_depth:
        depth += 1
        d = cur.getDef()
        if d is None:
            return None
        opc = d.getOpcode()
        if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.SUBPIECE, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            cur = d.getInput(0)
            if cur and cur.isConstant():
                return int(cur.getOffset())
            continue
        if opc in (PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR):
            a = eval_const_int(d.getInput(0), max_depth=4)
            b = eval_const_int(d.getInput(1), max_depth=4)
            if a is None or b is None:
                return None
            if opc == PcodeOp.INT_ADD: return a + b
            if opc == PcodeOp.INT_SUB: return a - b
            if opc == PcodeOp.INT_AND: return a & b
            if opc == PcodeOp.INT_OR:  return a | b
            if opc == PcodeOp.INT_XOR: return a ^ b
        return None
    return None

class ExternalOverrideDB:
    def __init__(self, path):
        self.path = path
        self.db = {}
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r") as fp:
                    self.db = json.load(fp)
        except Exception:
            self.db = {}

    def save(self):
        try:
            with open(self.path, "w") as fp:
                json.dump(self.db, fp, indent=2)
        except Exception:
            pass

    def get(self, name):
        if not name:
            return None
        return self.db.get(name)

    def ensure_entry(self, name):
        if name not in self.db:
            self.db[name] = {"traits": [], "params": {}}

class Step1dDetector:
    def __init__(self):
        self.decomp = DecompInterface()
        self.decomp.openProgram(currentProgram)
        self.findings = []
        self.call_hist = Counter()

        self.overrides_path = os.path.join(os.path.expanduser("~"), "tg_memcorr_external_overrides.json")
        self.overrides = ExternalOverrideDB(self.overrides_path)

    def resolve_call_name(self, op):
        addr = op.getSeqnum().getTarget()
        n = called_name_from_instruction(addr)
        if n:
            return n
        # fallback: decompiler target
        try:
            if op.getNumInputs() < 1:
                return None
            tgt = op.getInput(0)
            if tgt is None:
                return None
            if tgt.isAddress():
                f = currentProgram.getListing().getFunctionAt(tgt.getAddress())
                return f.getName() if f else None
            if tgt.isConstant():
                a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(tgt.getOffset())
                f = currentProgram.getListing().getFunctionAt(a)
                return f.getName() if f else None
            high = tgt.getHigh()
            if high and high.getSymbol():
                return high.getSymbol().getName()
        except Exception:
            pass
        return None

    def add_finding(self, func_name, addr, vuln_type, severity, details):
        self.findings.append({
            "func": func_name,
            "addr": str(addr),
            "type": vuln_type,
            "severity": severity,
            "details": details
        })

        paddr = addr
        if hasattr(paddr, "getPhysicalAddress"):
            paddr = paddr.getPhysicalAddress()

        if CONFIG["emit_bookmarks"]:
            try:
                bm = currentProgram.getBookmarkManager()
                bm.setBookmark(paddr, "Analysis", f"[TG_MEMCORR] {severity} {vuln_type}", details[:140])
            except Exception:
                pass

        if CONFIG["emit_comments"]:
            try:
                listing = currentProgram.getListing()
                cu = listing.getCodeUnitAt(paddr)
                if cu:
                    plate = f">>> TG_MEMCORR: {vuln_type} [{severity}] <<<\n{details}"
                    existing = cu.getComment(CodeUnit.PLATE_COMMENT)
                    if existing and vuln_type not in existing:
                        plate = existing + "\n" + plate
                    elif existing:
                        plate = existing
                    cu.setComment(CodeUnit.PLATE_COMMENT, plate)
                    cu.setComment(CodeUnit.EOL_COMMENT, f"[TG_MEMCORR] {severity} {vuln_type}")
            except Exception:
                pass

    def maybe_prompt_tag(self, callee_norm):
        """
        Prompt only when callee is external AND unknown.
        """
        if not CONFIG["interactive_external_tagging"]:
            return

        # Only prompt on externals (Ghidra knows import symbols as external functions).
        # If Ghidra can't resolve to an external function object, skip prompting (avoid noise).
        try:
            ext = currentProgram.getFunctionManager().getExternalFunction(callee_norm)
            if ext is None:
                return
        except Exception:
            return

        if callee_norm in DEFAULT_EXTERNALS:
            return
        if self.overrides.get(callee_norm):
            return

        print(f"\n[?] Unknown external '{callee_norm}'. Tag it for analysis?")
        print("    0) IGNORE")
        print("    1) BOUNDED_COPY_SINK (dst,len)  e.g., memcpy/memmove/strncpy/strncat")
        print("    2) BOUNDED_SET_SINK (dst,len)   e.g., memset")
        print("    3) UNBOUNDED_WRITE_SINK (dst)   e.g., strcpy/sprintf")
        ans = None
        try:
            ans = input("Select [0-3] (default 0): ").strip()
        except Exception:
            ans = "0"
        if ans == "":
            ans = "0"

        entry = {"traits": [], "params": {}}
        if ans == "1":
            entry["traits"] = ["BOUNDED_COPY_SINK"]
            entry["params"] = {"DST_ARG": 0, "LEN_ARG": 2}
        elif ans == "2":
            entry["traits"] = ["BOUNDED_SET_SINK"]
            entry["params"] = {"DST_ARG": 0, "LEN_ARG": 2}
        elif ans == "3":
            entry["traits"] = ["UNBOUNDED_WRITE_SINK"]
            entry["params"] = {"DST_ARG": 0}
        else:
            entry["traits"] = ["IGNORE"]

        self.overrides.db[callee_norm] = entry
        self.overrides.save()
        print(f"[*] Saved override for '{callee_norm}' to {self.overrides_path}\n")

    def classify_callee(self, callee_norm):
        # Overrides take precedence
        ov = self.overrides.get(callee_norm)
        if ov:
            return ov
        return DEFAULT_EXTERNALS.get(callee_norm)

    def analyze(self):
        print("=" * 70)
        print(" TG MemCorr Detector - Step 1d (Bounded copy stack overflow)")
        print("=" * 70)
        print(f"[*] Config: interactive_external_tagging={CONFIG['interactive_external_tagging']}, max_expr_depth={CONFIG['max_expr_depth']}")
        print(f"[*] External override DB: {os.path.join(os.path.expanduser('~'), 'tg_memcorr_external_overrides.json')}")
        funcs = list(currentProgram.getFunctionManager().getFunctions(True))
        if CONFIG["max_funcs"] is not None:
            funcs = funcs[: int(CONFIG["max_funcs"])]
        print(f"[*] Analyzing {len(funcs)} functions...\n")

        calls_seen = calls_named = sink_hits = 0

        for f in funcs:
            if f.isThunk() or f.isExternal():
                continue
            res = self.decomp.decompileFunction(f, CONFIG["decompile_timeout_s"], TaskMonitor.DUMMY)
            if not res.decompileCompleted():
                continue
            hf = res.getHighFunction()
            if hf is None:
                continue

            it = hf.getPcodeOps()
            while it.hasNext():
                op = it.next()
                if op.getOpcode() not in (PcodeOp.CALL, PcodeOp.CALLIND):
                    continue
                calls_seen += 1
                addr = op.getSeqnum().getTarget()

                raw = self.resolve_call_name(op)
                norm = normalize_func_name(raw)
                if not norm:
                    continue
                calls_named += 1
                self.call_hist[norm] += 1

                # Allow researcher to tag unknown externals (portability feature)
                self.maybe_prompt_tag(norm)

                spec = self.classify_callee(norm)
                if not spec:
                    continue
                traits = spec.get("traits", [])
                params = spec.get("params", {})

                if "IGNORE" in traits:
                    continue

                # Handle bounded copy / set sinks
                if "BOUNDED_COPY_SINK" in traits or "BOUNDED_SET_SINK" in traits:
                    dst_i = params.get("DST_ARG", 0)
                    len_i = params.get("LEN_ARG", 2)
                    # op input(0)=call target; args start at 1
                    if op.getNumInputs() <= 1 + max(dst_i, len_i):
                        continue
                    dst_vn = op.getInput(1 + dst_i)
                    len_vn = op.getInput(1 + len_i)

                    sb = stack_buf_from_ptr(dst_vn, hf)
                    if not sb:
                        continue  # Step 1d stays focused: stack destinations only
                    buf_name, buf_size, buf_off = sb
                    if buf_size is None:
                        continue

                    remaining = max(0, int(buf_size) - int(buf_off))

                    # Size classification
                    cval = eval_const_int(len_vn)
                    cmv = try_parse_const_minus_var(len_vn, CONFIG["max_expr_depth"])

                    if cval is not None:
                        # definite check
                        if cval > remaining:
                            details = f"{norm} writes {cval} bytes into stack buffer {buf_name}[{buf_size}]+{buf_off} (remaining={remaining})"
                            self.add_finding(f.getName(), addr, "STACK_OVERFLOW_BOUNDED_DEFINITE", "HIGH", details)
                            sink_hits += 1
                        else:
                            # safe (for this specific recovered size)
                            pass
                        continue

                    if cmv and CONFIG["flag_const_minus_var_size"] and cmv["kind"] == "CONST_MINUS_VAR":
                        details = f"{norm} writes with size expr (0x{cmv['const']:x} - {cmv['var']}) into stack buffer {buf_name}[{buf_size}]+{buf_off} (remaining={remaining}) | Heuristic: CONST-VAR may underflow -> huge size"
                        self.add_finding(f.getName(), addr, "STACK_WRITE_SIZE_UNDERFLOW", "HIGH", details)
                        sink_hits += 1
                        continue

                    if cmv and CONFIG["flag_var_minus_const_size"] and cmv["kind"] == "VAR_MINUS_CONST":
                        details = f"{norm} writes with size expr ({cmv['var']} - 0x{cmv['const']:x}) into stack buffer {buf_name}[{buf_size}]+{buf_off} (remaining={remaining}) | Heuristic: VAR-CONST may underflow if var<const"
                        self.add_finding(f.getName(), addr, "STACK_WRITE_SIZE_UNDERFLOW", "HIGH", details)
                        sink_hits += 1
                        continue

                    if CONFIG["emit_low_confidence"]:
                        details = f"{norm} writes into stack buffer {buf_name}[{buf_size}]+{buf_off} with non-constant size (remaining={remaining})"
                        self.add_finding(f.getName(), addr, "STACK_OVERFLOW_BOUNDED_CANDIDATE", "MEDIUM", details)
                        sink_hits += 1
                        continue

                # Handle unbounded write sinks if researcher tags them (optional)
                if "UNBOUNDED_WRITE_SINK" in traits:
                    dst_i = params.get("DST_ARG", 0)
                    if op.getNumInputs() <= 1 + dst_i:
                        continue
                    dst_vn = op.getInput(1 + dst_i)
                    sb = stack_buf_from_ptr(dst_vn, hf)
                    if not sb:
                        continue
                    buf_name, buf_size, buf_off = sb
                    details = f"{norm} unbounded write into stack buffer {buf_name}[{buf_size}]+{buf_off}"
                    self.add_finding(f.getName(), addr, "STACK_OVERFLOW_UNBOUNDED", "HIGH", details)
                    sink_hits += 1

        print(f"[*] Calls seen: {calls_seen} | named: {calls_named}")
        print(f"[*] Stack sink hits: {sink_hits}")
        print(f"[*] Findings: {len(self.findings)}")

        if CONFIG["print_top_calls"] and len(self.call_hist):
            print("\n[*] Top normalized call targets:")
            for name, cnt in self.call_hist.most_common(int(CONFIG["print_top_calls"])):
                print(f"    {name}: {cnt}")

        out_path = os.path.join(os.path.expanduser("~"), "memcorr_step1d_bounded_copy_stack_overflow.json")
        try:
            with open(out_path, "w") as fp:
                json.dump({
                    "findings": self.findings,
                    "config": CONFIG,
                    "top_calls": self.call_hist.most_common(200),
                    "overrides_path": self.overrides_path,
                }, fp, indent=2)
            print(f"[*] Results: {out_path}")
        except Exception:
            pass

def run():
    Step1dDetector().analyze()

run()
