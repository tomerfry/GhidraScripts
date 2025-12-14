# TG MemCorr Detector - Step 2b (Tainted / unchecked length in memcpy-like copies)
# @category Security
# @runtime PyGhidra
#
# Goal (incremental, practical):
#   Identify memcpy/memmove/__memcpy_chk-style copies where the *length* argument is likely attacker-influenced
#   and there is no obvious local bound-check (heuristic). This is a common precursor to OOB read/write bugs
#   (e.g., Heartbleed-class "length from packet controls copy length", or web/CGI parameter length driving copies).
#
# Notes:
#   - This is NOT a full proof of exploitability; it is a triage detector.
#   - We keep false positives down by prioritizing cases where destination is a stack buffer with a known size.
#   - Optional: interactive tagging of unknown externals as memcpy-like sinks (reuses tg_memcorr_external_overrides.json).
#
# Output:
#   Bookmarks + code comments + JSON under %USERPROFILE% (home dir).

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import CodeUnit
from collections import defaultdict
import json, os

CONFIG = {
    "max_pcode_depth": 14,
    "max_expr_depth": 22,
    "max_findings": 250,
    "interactive_external_tagging": True,
    "external_overrides_path": os.path.join(os.path.expanduser("~"), "tg_memcorr_external_overrides.json"),
    # If True, we still emit LOW findings when we see a plausible local check.
    "emit_checked_findings": False,
}

# Built-in sink specs (by normalized name)
# For __memcpy_chk(dest, src, len, destlen) we use COPY_LEN=2, COPY_DSTLEN=3
SINK_SPECS = {
    "memcpy":       {"traits": ["COPY"], "params": {"COPY_DST": 0, "COPY_LEN": 2}},
    "memmove":      {"traits": ["COPY"], "params": {"COPY_DST": 0, "COPY_LEN": 2}},
    "bcopy":        {"traits": ["COPY"], "params": {"COPY_DST": 1, "COPY_LEN": 2}},  # bcopy(src,dst,len)
    "__memcpy_chk": {"traits": ["COPY_CHK"], "params": {"COPY_DST": 0, "COPY_LEN": 2, "COPY_DSTLEN": 3}},
    "__memmove_chk":{"traits": ["COPY_CHK"], "params": {"COPY_DST": 0, "COPY_LEN": 2, "COPY_DSTLEN": 3}},
}

# Common taint sources: we treat their return (or a specified param) as attacker-influenced.
# This stays conservative; you can extend via overrides later.
TAINT_SOURCES = {
    "recv":   {"ret": True, "param": 1},
    "read":   {"ret": True, "param": 1},
    "fgets":  {"ret": True, "param": 0},
    "fread":  {"ret": False, "param": 0},
    "getenv": {"ret": True, "param": None},  # CGI often uses getenv("HTTP_COOKIE"), etc.
}

# -------------------------
# External overrides (interactive)
# -------------------------

def normalize_func_name(name):
    if not name:
        return None
    n = name
    # Common compiler/linker decorations
    if n.startswith("PTR_"):
        parts = n[4:].split("_")
        if parts:
            n = parts[0]
    n = n.lstrip("_")
    n = n.replace("_chk", "")
    # __GI___memcpy -> memcpy
    if n.startswith("GI__"):
        n = n[4:]
    if n.startswith("GI___"):
        n = n[5:]
    # glibc __memcpy_chk stays, we handle by also checking stripped variant
    return n.lower()

class ExternalOverrideDB:
    """
    Supports either:
      { "foo": {"traits":[...], "params": {...}}, ... }
    or:
      { "overrides": { ...same... } }
    """
    def __init__(self, path):
        self.path = path
        self.db = {}
        self._noask = set()
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r") as fp:
                    raw = json.load(fp)
                if isinstance(raw, dict) and "overrides" in raw and isinstance(raw["overrides"], dict):
                    raw = raw["overrides"]
                if isinstance(raw, dict):
                    # normalize keys to lowercase normalized names
                    for k, v in raw.items():
                        nk = normalize_func_name(k) or k
                        self.db[nk] = v
        except Exception:
            pass

    def save(self):
        try:
            # Persist as flat mapping (simpler for hand edits)
            with open(self.path, "w") as fp:
                json.dump(self.db, fp, indent=2, sort_keys=True)
        except Exception:
            pass

    def get(self, name):
        if not name:
            return None
        return self.db.get(normalize_func_name(name)) or self.db.get(name)

    def maybe_tag_unknown(self, raw_name):
        if not CONFIG.get("interactive_external_tagging", False):
            return
        if not raw_name:
            return
        norm = normalize_func_name(raw_name)
        if not norm or norm in SINK_SPECS or norm in self.db or norm in self._noask:
            return

        try:
            ans = askChoice(
                "TG MemCorr - External Tagging",
                "Unknown external '{}' (normalized '{}'). Tag as a copy sink?".format(raw_name, norm),
                ["No", "memcpy-like (dst,src,len)", "__memcpy_chk-like (dst,src,len,dstlen)", "Skip and don't ask again"],
                "No"
            )
            if ans == "memcpy-like (dst,src,len)":
                self.db[norm] = {"traits": ["COPY"], "params": {"COPY_DST": 0, "COPY_LEN": 2}}
                self.save()
            elif ans == "__memcpy_chk-like (dst,src,len,dstlen)":
                self.db[norm] = {"traits": ["COPY_CHK"], "params": {"COPY_DST": 0, "COPY_LEN": 2, "COPY_DSTLEN": 3}}
                self.save()
            elif ans == "Skip and don't ask again":
                self._noask.add(norm)
        except Exception:
            # headless or dialogs disabled
            pass


# -------------------------
# Core helpers
# -------------------------

def canonical_function(func):
    try:
        if func and func.isThunk():
            t = func.getThunkedFunction(False)
            return t if t else func
    except Exception:
        pass
    return func

def resolve_callee_name_from_pcode(op):
    """
    Try to resolve a CALL/CALLIND pcode op to a function name.
    Works for direct address, constant, and some simple indirections via HighSymbol names.
    """
    try:
        if op.getNumInputs() < 1:
            return None
        tgt = op.getInput(0)
        if not tgt:
            return None

        fm = currentProgram.getFunctionManager()

        if tgt.isAddress():
            f = fm.getFunctionAt(tgt.getAddress())
            if f:
                return canonical_function(f).getName()

        if tgt.isConstant():
            a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(tgt.getOffset())
            f = fm.getFunctionAt(a)
            if f:
                return canonical_function(f).getName()

        high = tgt.getHigh()
        if high and high.getSymbol():
            return high.getSymbol().getName()

        # fall back
        return None
    except Exception:
        return None

def is_stack_symbol_vn(vn):
    try:
        high = vn.getHigh() if vn else None
        if high and high.getSymbol():
            sym = high.getSymbol()
            if hasattr(sym, "getStorage"):
                st = sym.getStorage()
                if st and st.isStackStorage():
                    return True
        return False
    except Exception:
        return False

def peel_ptr(vn, depth=0):
    """Peel COPY/CAST/PTRSUB/PTRADD to get the 'base' pointer-like varnode."""
    if depth > CONFIG["max_expr_depth"] or not vn:
        return vn, 0
    off = 0
    try:
        d = vn.getDef()
        if not d:
            return vn, 0
        opc = d.getOpcode()
        if opc == PcodeOp.PTRSUB:
            base = d.getInput(0)
            o = d.getInput(1)
            if o and o.isConstant():
                off = int(o.getOffset())
            b2, o2 = peel_ptr(base, depth + 1)
            return b2, off + o2
        if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.PTRADD, PcodeOp.SUBPIECE, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            return peel_ptr(d.getInput(0), depth + 1)
    except Exception:
        pass
    return vn, off

def get_stack_buffer_info(vn):
    """
    If vn appears to reference a stack variable, return (name, size, offset).
    size is best-effort from data type length when available.
    """
    if not vn:
        return (None, None, 0)
    try:
        # peel pointer arithmetic first
        base, off = peel_ptr(vn)
        high = base.getHigh() if base else None
        if high and high.getSymbol():
            sym = high.getSymbol()
            name = sym.getName()
            size = None
            try:
                dt = high.getDataType()
                if dt:
                    size = int(dt.getLength())
            except Exception:
                pass
            if is_stack_symbol_vn(base):
                return (name, size, off)
        return (None, None, off)
    except Exception:
        return (None, None, 0)

def const_value(vn):
    try:
        if vn and vn.isConstant():
            return int(vn.getOffset())
    except Exception:
        pass
    return None

def expr_desc(vn, depth=0):
    """
    Render a simple symbolic description for vn (for debugging + heuristics).
    Returns dict {'kind':..., ...} to keep it machine-usable.
    """
    if depth > CONFIG["max_expr_depth"] or not vn:
        return {"kind": "unknown"}
    cv = const_value(vn)
    if cv is not None:
        return {"kind": "const", "v": cv}
    try:
        high = vn.getHigh()
        if high and high.getSymbol():
            sym = high.getSymbol()
            if sym.isParameter():
                return {"kind": "param", "index": int(sym.getOrdinal()), "name": sym.getName()}
            if sym.isGlobal():
                return {"kind": "global", "name": sym.getName()}
            if is_stack_symbol_vn(vn):
                return {"kind": "stack", "name": sym.getName()}
            return {"kind": "var", "name": sym.getName()}
    except Exception:
        pass
    try:
        d = vn.getDef()
        if not d:
            return {"kind": "unknown"}
        opc = d.getOpcode()
        if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.SUBPIECE, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            return expr_desc(d.getInput(0), depth + 1)
        if opc == PcodeOp.INT_ADD:
            return {"kind": "add", "a": expr_desc(d.getInput(0), depth+1), "b": expr_desc(d.getInput(1), depth+1)}
        if opc == PcodeOp.INT_SUB:
            return {"kind": "sub", "a": expr_desc(d.getInput(0), depth+1), "b": expr_desc(d.getInput(1), depth+1)}
        if opc == PcodeOp.INT_MULT:
            return {"kind": "mul", "a": expr_desc(d.getInput(0), depth+1), "b": expr_desc(d.getInput(1), depth+1)}
        if opc == PcodeOp.LOAD:
            return {"kind": "load", "ptr": expr_desc(d.getInput(1), depth+1)}
        if opc == PcodeOp.MULTIEQUAL:
            # phi node - summarize
            parts = []
            for i in range(d.getNumInputs()):
                parts.append(expr_desc(d.getInput(i), depth+1))
            return {"kind": "phi", "alts": parts[:4]}
    except Exception:
        pass
    return {"kind": "unknown"}

def has_const_minus_var_pattern(ed):
    """Return (True, const_val, var_kind) for patterns like CONST - VAR (potential underflow)."""
    if not ed or ed.get("kind") != "sub":
        return (False, None, None)
    a = ed.get("a"); b = ed.get("b")
    if a and a.get("kind") == "const" and b and b.get("kind") != "const":
        return (True, a.get("v"), b.get("kind"))
    return (False, None, None)

def trace_taint(vn, extern_overrides, depth=0):
    """
    Lightweight taint: True if vn is parameter, global with suggestive name, return from known sources,
    or derived from tainted values by simple ops.
    """
    if depth > CONFIG["max_pcode_depth"] or not vn:
        return (False, "unknown")

    cv = const_value(vn)
    if cv is not None:
        return (False, "const")

    try:
        high = vn.getHigh()
        if high and high.getSymbol():
            sym = high.getSymbol()
            nm = sym.getName() or ""
            if sym.isParameter():
                return (True, "param:{}".format(nm))
            if sym.isGlobal():
                # heuristic: common input-ish globals
                for ind in ("cookie", "query", "input", "user", "http", "request", "env", "argv", "cgi", "post", "get_", "form", "param"):
                    if ind in nm.lower():
                        return (True, "global:{}".format(nm))
    except Exception:
        pass

    d = None
    try:
        d = vn.getDef()
    except Exception:
        d = None
    if not d:
        return (False, "leaf")

    opc = d.getOpcode()

    if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.SUBPIECE, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
        return trace_taint(d.getInput(0), extern_overrides, depth + 1)

    if opc in (PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT):
        for i in range(d.getNumInputs()):
            t, s = trace_taint(d.getInput(i), extern_overrides, depth + 1)
            if t:
                return (True, s)
        return (False, "arith")

    if opc == PcodeOp.LOAD:
        t, s = trace_taint(d.getInput(1), extern_overrides, depth + 1)
        return (t, "load({})".format(s))

    if opc in (PcodeOp.CALL, PcodeOp.CALLIND):
        callee = resolve_callee_name_from_pcode(d)
        if callee:
            norm = normalize_func_name(callee)
            spec = extern_overrides.get(callee) or TAINT_SOURCES.get(norm)
            if spec:
                if spec.get("ret", False):
                    return (True, "ret:{}".format(norm))
        return (False, "ret:{}".format(callee or "?"))

    if opc == PcodeOp.MULTIEQUAL:
        for i in range(d.getNumInputs()):
            t, s = trace_taint(d.getInput(i), extern_overrides, depth + 1)
            if t:
                return (True, s)
        return (False, "phi")

    return (False, "other")

def find_obvious_len_check(hf, len_vn):
    """
    Heuristic: detect a compare involving (len_vn or its peeled base) anywhere in function pcode.
    This is imprecise (no dominance), but helps reduce noise.
    """
    if not hf or not len_vn:
        return False
    try:
        # Compare using peeled / canonical varnode if possible
        base, _ = peel_ptr(len_vn)
        candidates = set([len_vn, base])
    except Exception:
        candidates = set([len_vn])

    try:
        it = hf.getPcodeOps()
        while it.hasNext():
            op = it.next()
            opc = op.getOpcode()
            if opc in (PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL,
                       PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL):
                a = op.getInput(0); b = op.getInput(1)
                if a in candidates or b in candidates:
                    return True
    except Exception:
        pass
    return False


# -------------------------
# Finding / UI
# -------------------------

def add_bookmark_and_comment(paddr, vuln_type, severity, details):
    try:
        bm = currentProgram.getBookmarkManager()
        bm.setBookmark(paddr, "Analysis", "[TG_MEMCORR] {} {}".format(severity, vuln_type), details[:80])
    except Exception:
        pass
    try:
        listing = currentProgram.getListing()
        cu = listing.getCodeUnitAt(paddr)
        if cu:
            plate = ">>> TG_MEMCORR: {} [{}] <<<\n{}".format(vuln_type, severity, details)
            existing = cu.getComment(CodeUnit.PLATE_COMMENT)
            if existing and vuln_type not in existing:
                plate = existing + "\n" + plate
            elif existing:
                plate = existing
            cu.setComment(CodeUnit.PLATE_COMMENT, plate)
            cu.setComment(CodeUnit.EOL_COMMENT, "[TG_MEMCORR] {} {}".format(severity, vuln_type))
    except Exception:
        pass

# -------------------------
# Main analysis
# -------------------------

def run():
    print("=" * 70)
    print(" TG MemCorr Detector - Step 2b (Tainted/unchecked memcpy length)")
    print("=" * 70)
    print("[*] Config: interactive_external_tagging={}, max_findings={}".format(
        CONFIG["interactive_external_tagging"], CONFIG["max_findings"]))
    print("[*] External override DB: {}".format(CONFIG["external_overrides_path"]))

    extern_overrides = ExternalOverrideDB(CONFIG["external_overrides_path"])
    di = DecompInterface()
    di.openProgram(currentProgram)

    findings = []
    seen_calls = 0
    named_calls = 0
    sink_hits = 0

    funcs = list(currentProgram.getFunctionManager().getFunctions(True))
    print("[*] Analyzing {} functions...".format(len(funcs)))

    for idx, func in enumerate(funcs):
        try:
            if func.isThunk() or func.isExternal():
                continue
        except Exception:
            pass

        if len(findings) >= CONFIG["max_findings"]:
            break

        res = di.decompileFunction(func, 60, TaskMonitor.DUMMY)
        if not res or not res.decompileCompleted():
            continue
        hf = res.getHighFunction()
        if not hf:
            continue

        ops = []
        it = hf.getPcodeOps()
        while it.hasNext():
            ops.append(it.next())

        for op in ops:
            if len(findings) >= CONFIG["max_findings"]:
                break

            opc = op.getOpcode()
            if opc not in (PcodeOp.CALL, PcodeOp.CALLIND):
                continue

            seen_calls += 1
            call_addr = op.getSeqnum().getTarget()
            callee = resolve_callee_name_from_pcode(op)
            if not callee:
                continue
            named_calls += 1

            # unknown external tagging (only if external-ish)
            extern_overrides.maybe_tag_unknown(callee)

            norm = normalize_func_name(callee)
            spec = SINK_SPECS.get(norm) or SINK_SPECS.get(callee) or extern_overrides.get(callee)
            if not spec:
                continue

            traits = spec.get("traits", [])
            params = spec.get("params", {})

            if "COPY" not in traits and "COPY_CHK" not in traits:
                continue

            dst_i = int(params.get("COPY_DST", 0))
            len_i = int(params.get("COPY_LEN", 2))
            dstlen_i = int(params.get("COPY_DSTLEN", -1))
            # CALL pcode inputs: [target, arg0, arg1, ...]
            if op.getNumInputs() <= max(dst_i, len_i, dstlen_i if dstlen_i >= 0 else 0) + 1:
                continue

            dst_vn = op.getInput(dst_i + 1)
            len_vn = op.getInput(len_i + 1)
            dstlen_vn = op.getInput(dstlen_i + 1) if (dstlen_i >= 0 and op.getNumInputs() > dstlen_i + 1) else None

            sink_hits += 1

            # Destination stack?
            stack_name, stack_size, stack_off = get_stack_buffer_info(dst_vn)
            is_stack = stack_name is not None

            # Length expression details
            len_const = const_value(len_vn)
            len_ed = expr_desc(len_vn)
            underflow_like, cst, var_kind = has_const_minus_var_pattern(len_ed)

            # Taint on length
            len_tainted, len_src = trace_taint(len_vn, extern_overrides)

            # Obvious check?
            has_check = find_obvious_len_check(hf, len_vn)

            # __memcpy_chk: compare len vs dstlen if possible
            dstlen_const = const_value(dstlen_vn) if dstlen_vn else None

            # Decide severity and type
            vuln_type = None
            severity = None
            details = None

            if is_stack and stack_size and len_const is not None:
                if len_const > stack_size:
                    vuln_type = "STACK_COPY_LEN_OVERFLOW"
                    severity = "HIGH"
                    details = "{} copies {} bytes into stack {}[{}]".format(norm, len_const, stack_name, stack_size)
                else:
                    continue  # definitely safe for this heuristic

            elif is_stack and stack_size and underflow_like:
                vuln_type = "STACK_COPY_LEN_UNDERFLOW"
                severity = "HIGH"
                details = "{} length looks like CONST-VAR ({} - ...) into stack {}[{}]".format(norm, cst, stack_name, stack_size)

            elif "COPY_CHK" in traits and dstlen_vn is not None:
                # If dstlen is constant and small but len is variable/tainted -> still interesting
                if dstlen_const is not None and len_const is not None and len_const > dstlen_const:
                    vuln_type = "COPY_CHK_LEN_GT_DSTLEN"
                    severity = "HIGH"
                    details = "{} len {} > dstlen {}".format(norm, len_const, dstlen_const)
                elif len_tainted and not has_check and is_stack:
                    vuln_type = "TAINTED_LEN_COPY_CHK_TO_STACK"
                    severity = "MEDIUM" if stack_size is None else "HIGH"
                    details = "{} tainted length ({}) into stack {}[{}]; dstlen={} check unknown".format(
                        norm, len_src, stack_name, stack_size if stack_size else "?", dstlen_const if dstlen_const is not None else "var")
                elif len_tainted and not has_check and not is_stack:
                    vuln_type = "TAINTED_LEN_COPY_CHK"
                    severity = "MEDIUM"
                    details = "{} tainted length ({}) with no obvious local check".format(norm, len_src)

            else:
                # Generic memcpy/memmove
                if len_tainted and not has_check:
                    if is_stack:
                        vuln_type = "TAINTED_LEN_COPY_TO_STACK"
                        severity = "HIGH" if stack_size else "MEDIUM"
                        details = "{} tainted length ({}) into stack {}[{}]{}".format(
                            norm, len_src, stack_name, stack_size if stack_size else "?",
                            " +{}".format(stack_off) if stack_off else "")
                    else:
                        vuln_type = "TAINTED_LEN_COPY"
                        severity = "MEDIUM"
                        details = "{} tainted length ({}) with no obvious check".format(norm, len_src)
                elif has_check and CONFIG.get("emit_checked_findings", False):
                    vuln_type = "LEN_CHECK_PRESENT_COPY"
                    severity = "LOW"
                    details = "{} length has some compare in function; manual review".format(norm)

            if vuln_type:
                # Normalize address
                paddr = call_addr
                try:
                    if hasattr(paddr, "getPhysicalAddress"):
                        paddr = paddr.getPhysicalAddress()
                except Exception:
                    pass

                findings.append({
                    "func": func.getName(),
                    "addr": str(call_addr),
                    "type": vuln_type,
                    "severity": severity,
                    "details": details,
                    "callee": callee,
                    "len_expr": len_ed,
                    "len_const": len_const,
                    "dst_stack": {"name": stack_name, "size": stack_size, "off": stack_off} if is_stack else None,
                    "has_len_check": bool(has_check),
                })
                add_bookmark_and_comment(paddr, vuln_type, severity, details)

    print("\n[*] Calls seen: {} | named: {}".format(seen_calls, named_calls))
    print("[*] Copy sinks hit: {}".format(sink_hits))
    print("[*] Findings: {}".format(len(findings)))

    out_path = os.path.join(os.path.expanduser("~"), "memcorr_step2b_len_taint_memcpy.json")
    try:
        with open(out_path, "w") as fp:
            json.dump({"findings": findings, "config": CONFIG}, fp, indent=2)
        print("[*] Results: {}".format(out_path))
    except Exception:
        print("[!] Failed writing results JSON to {}".format(out_path))

run()
