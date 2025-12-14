# TG_memcorr_step1e7_interproc_len_resolution_plus.py
# TG MemCorr Detector - Step 1e7
#
# Interproc stack-dst tracking + improved length constant folding.
#
# This step targets cases where the callee bounds a copy length via a phi/MULTIEQUAL:
#   len2 = (len > K) ? K : len
# which often appears as MULTIEQUAL(const_materialized(K), param_len)
#
# Step 1e6 saw: phi2(unknown, param). Here we try harder to fold "unknown" into const.
#
# @category Security
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import CodeUnit
from collections import defaultdict
import json
import os

CONFIG = {
    "decompile_timeout_s": 60,
    "max_expr_depth": 40,
    "emit_bookmarks": True,
    "emit_comments": True,
    "emit_low_confidence": True,
}

# External sinks we summarize inside internal functions
SINK_DB = {
    "memcpy":          {"params": {"DST_ARG": 0, "LEN_ARG": 2}},
    "memmove":         {"params": {"DST_ARG": 0, "LEN_ARG": 2}},
    "bcopy":           {"params": {"DST_ARG": 1, "LEN_ARG": 2}},
    "strncpy":         {"params": {"DST_ARG": 0, "LEN_ARG": 2}},
    "strncat":         {"params": {"DST_ARG": 0, "LEN_ARG": 2}},
    "__memcpy_chk":    {"params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "__memmove_chk":   {"params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "__strncpy_chk":   {"params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
    "__strncat_chk":   {"params": {"DST_ARG": 0, "LEN_ARG": 2, "OBJLEN_ARG": 3}},
}

ALIASES = {
    "__builtin___memcpy_chk": "__memcpy_chk",
    "__builtin___memmove_chk": "__memmove_chk",
    "__builtin___strncpy_chk": "__strncpy_chk",
    "__builtin___strncat_chk": "__strncat_chk",
}

def normalize_func_name(name):
    if not name:
        return None
    n = name
    if n.startswith("PTR_"):
        rest = n[4:]
        parts = rest.rsplit("_", 1)
        if parts and parts[0]:
            n = parts[0]
    for pfx in ("imp.", "thunk_", "__imp_", "plt_", "j_"):
        if n.startswith(pfx):
            n = n[len(pfx):]
    if "@@GLIBC" in n:
        n = n.split("@@GLIBC")[0]
    if "@plt" in n:
        n = n.replace("@plt", "")
    if n.endswith(".plt"):
        n = n[:-4]
    if n.startswith("_") and not n.startswith("__"):
        n = n.lstrip("_")
    n = ALIASES.get(n, n)
    return n

def canonical_function(func):
    try:
        if func and func.isThunk():
            t = func.getThunkedFunction(False)
            return t if t else func
    except Exception:
        pass
    return func

def resolve_callee_from_instruction(callsite_addr):
    try:
        ins = currentProgram.getListing().getInstructionAt(callsite_addr)
        if not ins:
            return (None, None)
        flows = ins.getFlows()
        if not flows:
            return (None, None)
        dst = flows[0]
        fm = currentProgram.getFunctionManager()
        f = fm.getFunctionAt(dst)
        if f:
            f = canonical_function(f)
            return (f, f.getName())
        sym = currentProgram.getSymbolTable().getPrimarySymbol(dst)
        return (None, sym.getName() if sym else None)
    except Exception:
        return (None, None)

def resolve_callee_from_pcode(op):
    try:
        if op.getNumInputs() < 1:
            return (None, None)
        tgt = op.getInput(0)
        if not tgt:
            return (None, None)
        fm = currentProgram.getFunctionManager()
        if tgt.isAddress():
            f = fm.getFunctionAt(tgt.getAddress())
            if f:
                f = canonical_function(f)
                return (f, f.getName())
        if tgt.isConstant():
            a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(tgt.getOffset())
            f = fm.getFunctionAt(a)
            if f:
                f = canonical_function(f)
                return (f, f.getName())
        high = tgt.getHigh()
        if high and high.getSymbol():
            return (None, high.getSymbol().getName())
    except Exception:
        pass
    return (None, None)

def to_signed64(x):
    x = int(x) & ((1 << 64) - 1)
    if x & (1 << 63):
        return x - (1 << 64)
    return x

def is_stack_storage(highsym):
    try:
        st = highsym.getStorage()
        return st and st.isStackStorage()
    except Exception:
        return False

def peel_ptr_expr(vn, max_depth):
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
        if opc == PcodeOp.MULTIEQUAL:
            cur = d.getInput(0); continue
        if opc == PcodeOp.PTRSUB:
            k = d.getInput(1)
            if k and k.isConstant():
                off += to_signed64(k.getOffset())
            cur = d.getInput(0); continue
        if opc == PcodeOp.PTRADD:
            idx = d.getInput(1)
            esz = d.getInput(2) if d.getNumInputs() > 2 else None
            if idx and idx.isConstant():
                delta = to_signed64(idx.getOffset())
                if esz and esz.isConstant():
                    delta *= to_signed64(esz.getOffset())
                off += delta
            cur = d.getInput(0); continue
        if opc == PcodeOp.INT_ADD:
            rhs = d.getInput(1)
            if rhs and rhs.isConstant():
                off += to_signed64(rhs.getOffset())
            cur = d.getInput(0); continue
        if opc == PcodeOp.INT_SUB:
            rhs = d.getInput(1)
            if rhs and rhs.isConstant():
                off -= to_signed64(rhs.getOffset())
            cur = d.getInput(0); continue
        break
    return cur, int(off)

def map_stack_offset_to_local(abs_off_signed, hf):
    lsm = hf.getLocalSymbolMap()
    if not lsm:
        return None
    for sym in lsm.getSymbols():
        if not is_stack_storage(sym):
            continue
        st = sym.getStorage()
        min_off = max_off = None
        for v in st.getVarnodes():
            if v.getAddress().getAddressSpace().isStackSpace():
                o = to_signed64(v.getAddress().getOffset())
                sz = int(v.getSize())
                min_off = o if min_off is None else min(min_off, o)
                max_off = (o + sz) if max_off is None else max(max_off, o + sz)
        if min_off is not None and max_off is not None and min_off <= abs_off_signed < max_off:
            return (sym.getName(), int(sym.getSize()), int(abs_off_signed - min_off))
    return None

def stack_buf_from_ptr(vn, hf):
    if vn is None or hf is None:
        return None
    base, add_off = peel_ptr_expr(vn, CONFIG["max_expr_depth"])

    # direct stack varnode
    try:
        if base and base.getAddress() and base.getAddress().getAddressSpace().isStackSpace():
            abs_off = to_signed64(base.getAddress().getOffset()) + int(add_off)
            m = map_stack_offset_to_local(abs_off, hf)
            if m:
                return m
    except Exception:
        pass

    # HighSymbol stack storage
    try:
        high = base.getHigh() if base else None
        if high and high.getSymbol() and is_stack_storage(high.getSymbol()):
            sym = high.getSymbol()
            return (sym.getName(), int(sym.getSize()), int(add_off))
    except Exception:
        pass

    # SP-based UNIQUE
    try:
        if base and base.isRegister():
            sp = currentProgram.getCompilerSpec().getStackPointer()
            if sp and base.getAddress() == sp.getAddress():
                abs_off = int(add_off)
                m = map_stack_offset_to_local(abs_off, hf)
                if m:
                    return m
    except Exception:
        pass

    return None

def base_param_index(vn):
    if vn is None:
        return None
    base, _ = peel_ptr_expr(vn, CONFIG["max_expr_depth"])
    try:
        high = base.getHigh() if base else None
        if high:
            hs = high.getSymbol()
            if hs and hs.isParameter():
                return int(hs.getCategoryIndex())
    except Exception:
        return None
    return None

# ---------- Constant folding for lengths ----------
def _mask(bits):
    if bits <= 0:
        return 0
    return (1 << bits) - 1

def _vn_bits(vn):
    try:
        return int(vn.getSize()) * 8
    except Exception:
        return 64

def eval_const(vn, max_depth=28, _seen=None):
    """Try to evaluate vn to an integer constant by following def-use through common ops."""
    if vn is None:
        return None
    if _seen is None:
        _seen = set()
    vid = id(vn)
    if vid in _seen:
        return None
    _seen.add(vid)

    try:
        if vn.isConstant():
            return int(vn.getOffset())
    except Exception:
        pass

    d = None
    try:
        d = vn.getDef()
    except Exception:
        d = None
    if not d or max_depth <= 0:
        return None

    opc = d.getOpcode()

    # unary pass-through
    if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.SUBPIECE, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
        return eval_const(d.getInput(0), max_depth-1, _seen)

    # simple binops
    if opc in (PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT,
               PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR,
               PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT):
        a = eval_const(d.getInput(0), max_depth-1, _seen)
        b = eval_const(d.getInput(1), max_depth-1, _seen)
        if a is None or b is None:
            return None
        bits = _vn_bits(vn)
        m = _mask(bits)
        if opc == PcodeOp.INT_ADD:   return (a + b) & m
        if opc == PcodeOp.INT_SUB:   return (a - b) & m
        if opc == PcodeOp.INT_MULT:  return (a * b) & m
        if opc == PcodeOp.INT_AND:   return (a & b) & m
        if opc == PcodeOp.INT_OR:    return (a | b) & m
        if opc == PcodeOp.INT_XOR:   return (a ^ b) & m
        if opc == PcodeOp.INT_LEFT:  return (a << b) & m
        if opc == PcodeOp.INT_RIGHT: return ((a & m) >> b) & m
        if opc == PcodeOp.INT_SRIGHT:
            sign = 1 << (bits - 1)
            sa = (a & m)
            if sa & sign:
                sa = sa - (1 << bits)
            return (sa >> b) & m

    # phi: if all inputs fold to same const, return it
    if opc == PcodeOp.MULTIEQUAL:
        consts = []
        for i in range(d.getNumInputs()):
            ci = eval_const(d.getInput(i), max_depth-1, _seen)
            consts.append(ci)
        if consts and all(c is not None for c in consts) and len(set(consts)) == 1:
            return int(consts[0])
        return None

    return None

def len_desc(vn):
    c = eval_const(vn)
    if c is not None:
        return {"kind": "const", "value": int(c)}

    pi = base_param_index(vn)
    if pi is not None:
        return {"kind": "param", "index": int(pi)}

    d = vn.getDef() if vn else None
    if d:
        opc = d.getOpcode()
        if opc == PcodeOp.MULTIEQUAL and d.getNumInputs() == 2:
            return {"kind": "phi2", "a": len_desc(d.getInput(0)), "b": len_desc(d.getInput(1))}
    return {"kind": "unknown"}

class Detector:
    def __init__(self):
        self.decomp = DecompInterface()
        self.decomp.openProgram(currentProgram)
        self.internal_summaries = defaultdict(list)
        self.findings = []

    def add_finding(self, func_name, addr, vuln_type, severity, details):
        self.findings.append({"func": func_name, "addr": str(addr), "type": vuln_type, "severity": severity, "details": details})

        paddr = addr
        if hasattr(paddr, "getPhysicalAddress"):
            paddr = paddr.getPhysicalAddress()

        if CONFIG["emit_bookmarks"]:
            try:
                currentProgram.getBookmarkManager().setBookmark(
                    paddr, "Analysis",
                    "[TG_MEMCORR] {} {}".format(severity, vuln_type),
                    details[:160]
                )
            except Exception:
                pass

        if CONFIG["emit_comments"]:
            try:
                cu = currentProgram.getListing().getCodeUnitAt(paddr)
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

    def build_internal_summaries(self, funcs):
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

                addr = op.getSeqnum().getTarget()
                _, raw = resolve_callee_from_instruction(addr)
                if not raw:
                    _, raw = resolve_callee_from_pcode(op)
                norm = normalize_func_name(raw)
                if not norm:
                    continue

                spec = SINK_DB.get(norm)
                if not spec:
                    continue

                params = spec["params"]
                dst_i = params["DST_ARG"]
                len_i = params["LEN_ARG"]
                if op.getNumInputs() <= 1 + max(dst_i, len_i):
                    continue

                dst_vn = op.getInput(1 + dst_i)
                len_vn = op.getInput(1 + len_i)

                dpi = base_param_index(dst_vn)
                if dpi is None:
                    continue

                self.internal_summaries[str(f.getEntryPoint())].append({
                    "callee": f.getName(),
                    "callee_entry": str(f.getEntryPoint()),
                    "sink": norm,
                    "dst_param": int(dpi),
                    "len_desc": len_desc(len_vn),
                })

    def resolve_called_internal(self, op, call_addr):
        tf, _ = resolve_callee_from_instruction(call_addr)
        if tf:
            return canonical_function(tf)
        tf2, _ = resolve_callee_from_pcode(op)
        if tf2:
            return canonical_function(tf2)
        return None

    def classify_len_at_callsite(self, ld, args):
        kind = ld.get("kind")
        if kind == "const":
            return ("const", int(ld["value"]))
        if kind == "param":
            idx = int(ld["index"])
            if 0 <= idx < len(args):
                c = eval_const(args[idx])
                if c is not None:
                    return ("const", int(c))
            return ("param", idx)
        if kind == "phi2":
            a = self.classify_len_at_callsite(ld["a"], args)
            b = self.classify_len_at_callsite(ld["b"], args)
            if a[0] == "const" and b[0] == "const":
                return ("const", max(int(a[1]), int(b[1])))
            return ("phi2", a, b)
        return ("unknown",)

    def analyze_callsites(self, funcs):
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

                call_addr = op.getSeqnum().getTarget()
                callee_func = self.resolve_called_internal(op, call_addr)
                if not callee_func:
                    continue

                summaries = self.internal_summaries.get(str(callee_func.getEntryPoint()))
                if not summaries:
                    continue

                args = [op.getInput(i) for i in range(1, op.getNumInputs())]

                for s in summaries:
                    dst_pi = s["dst_param"]
                    if dst_pi >= len(args):
                        continue

                    sb = stack_buf_from_ptr(args[dst_pi], hf)
                    if not sb:
                        continue

                    buf_name, buf_size, buf_off = sb
                    remaining = max(0, int(buf_size) - int(buf_off))

                    ld = s["len_desc"]
                    resolved = self.classify_len_at_callsite(ld, args)

                    if resolved[0] == "const":
                        n = int(resolved[1])
                        if n > remaining:
                            self.add_finding(
                                f.getName(), call_addr,
                                "INTERPROC_STACK_OVERFLOW_DEFINITE", "HIGH",
                                "Interproc: {}->{} writes {} bytes into stack arg {}[{}]+{} (remaining={}). len_desc={}".format(
                                    s["callee"], s["sink"], n, buf_name, buf_size, buf_off, remaining, ld
                                )
                            )
                        elif CONFIG["emit_low_confidence"]:
                            self.add_finding(
                                f.getName(), call_addr,
                                "INTERPROC_STACK_WRITE_SAFE", "LOW",
                                "Interproc: {}->{} writes {} bytes into stack arg {}[{}]+{} (remaining={}) [resolved safe]. len_desc={}".format(
                                    s["callee"], s["sink"], n, buf_name, buf_size, buf_off, remaining, ld
                                )
                            )
                    else:
                        if CONFIG["emit_low_confidence"]:
                            self.add_finding(
                                f.getName(), call_addr,
                                "INTERPROC_STACK_WRITE_CANDIDATE", "MEDIUM",
                                "Interproc: {} contains {} writing to dst param{}; caller passes stack arg {}[{}]+{}; length not resolved (resolved={}). len_desc={}".format(
                                    s["callee"], s["sink"], dst_pi, buf_name, buf_size, buf_off, resolved, ld
                                )
                            )

    def run(self):
        print("=" * 70)
        print(" TG MemCorr Detector - Step 1e7 (Interproc: len resolution + const folding)")
        print("=" * 70)

        funcs = list(currentProgram.getFunctionManager().getFunctions(True))
        print("[*] Indexing {} functions...\n".format(len(funcs)))

        self.build_internal_summaries(funcs)
        self.analyze_callsites(funcs)

        total_summ = sum(len(v) for v in self.internal_summaries.values())
        print("\n[*] Internal sink summaries: {} across {} functions".format(total_summ, len(self.internal_summaries)))
        print("[*] Findings: {}".format(len(self.findings)))

        out_path = os.path.join(os.path.expanduser("~"), "memcorr_step1e7_interproc_len_resolution_plus.json")
        try:
            with open(out_path, "w") as fp:
                json.dump({"findings": self.findings, "config": CONFIG, "internal_summaries": self.internal_summaries}, fp, indent=2)
            print("[*] Results: {}".format(out_path))
        except Exception:
            pass

def run():
    Detector().run()

run()
