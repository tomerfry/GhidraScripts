# TG_memcorr_step1b_stack_bounded_overflow.py
# Memory Corruption Detector (Step 1b) - Stack Buffer Overflows via memcpy/strncpy (constant sizes)
# Also prints a call-name histogram to debug call target resolution.
# @category Security
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import CodeUnit
import json, os
from collections import Counter

CONFIG = {
    "decompile_timeout_s": 60,
    "max_funcs": None,          # None => all
    "max_trace_depth": 12,
    "emit_bookmarks": True,
    "emit_comments": True,
    "print_top_calls": 30,
    "debug": False,
}

# Sinks where the *write length* is an argument we can compare to dst buffer size
BOUNDED_LEN_SINKS = {
    # name -> (dst_arg_index, len_arg_index)  0-based in C signature
    "memcpy":  (0, 2),
    "memmove": (0, 2),
    "bcopy":   (1, 2),   # bcopy(src, dst, len)
    "strncpy": (0, 2),
    "strncat": (0, 2),   # strncat(dst, src, n) can overflow if dst not big enough
}

# Still report unbounded sinks if present (dst only)
UNBOUNDED_SINKS = {
    "gets": 0,
    "strcpy": 0,
    "strcat": 0,
    "sprintf": 0,
    "vsprintf": 0,
}

ALIASES = {
    "__strcpy_chk": "strcpy",
    "__strcat_chk": "strcat",
    "__sprintf_chk": "sprintf",
    "strcpy_chk": "strcpy",
    "strcat_chk": "strcat",
    "sprintf_chk": "sprintf",
}

def normalize_func_name(name):
    if not name:
        return None
    n = name

    # PTR_* import pointer patterns
    if n.startswith("PTR_"):
        # Typical: PTR_memcpy_00401230 or PTR_memcpy_0
        rest = n[4:]
        parts = rest.rsplit("_", 1)
        if parts and parts[0]:
            n = parts[0]

    # Strip common prefixes
    for pfx in ("imp.", "thunk_", "__imp_", "plt_", "j_"):
        if n.startswith(pfx):
            n = n[len(pfx):]

    # Strip version / plt suffixes
    if "@@" in n:
        n = n.split("@@")[0]
    if "@plt" in n:
        n = n.replace("@plt", "")
    if n.endswith(".plt"):
        n = n[:-4]

    # Leading underscores and fortify
    n = n.lstrip("_")
    n = n.replace("_chk", "")

    n = ALIASES.get(n, n)
    return n

def is_stack_storage(symbol):
    try:
        storage = symbol.getStorage()
        return storage and storage.isStackStorage()
    except Exception:
        return False

def peel_varnode(vn, max_depth=16):
    """
    Strip pcode wrappers; return (base_vn, accumulated_offset_bytes)
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
            off_vn = d.getInput(1)
            if off_vn and off_vn.isConstant():
                off += int(off_vn.getOffset())
            cur = d.getInput(0); continue

        if opc == PcodeOp.PTRADD:
            idx_vn = d.getInput(1)
            elem_vn = d.getInput(2) if d.getNumInputs() > 2 else None
            if idx_vn and idx_vn.isConstant():
                delta = int(idx_vn.getOffset())
                if elem_vn and elem_vn.isConstant():
                    delta *= int(elem_vn.getOffset())
                off += delta
            cur = d.getInput(0); continue

        if opc == PcodeOp.INT_ADD:
            rhs = d.getInput(1)
            if rhs and rhs.isConstant():
                off += int(rhs.getOffset())
            cur = d.getInput(0); continue

        break
    return cur, off

def eval_const_int(vn, max_depth=12):
    """
    Best-effort constant folding for common patterns:
      const
      COPY/CAST/SUBPIECE/ZEXT/SEXT of const
      INT_AND/INT_OR/INT_XOR with consts
      INT_ADD/INT_SUB with consts
    Returns Python int or None.
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
            break
        opc = d.getOpcode()

        if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.SUBPIECE, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            cur = d.getInput(0)
            if cur and cur.isConstant():
                return int(cur.getOffset())
            continue

        # Binary ops with constant operands
        if opc in (PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR):
            a = d.getInput(0); b = d.getInput(1)
            ca = eval_const_int(a, max_depth=2) if a else None
            cb = eval_const_int(b, max_depth=2) if b else None
            if ca is None or cb is None:
                break
            if opc == PcodeOp.INT_ADD: return ca + cb
            if opc == PcodeOp.INT_SUB: return ca - cb
            if opc == PcodeOp.INT_AND: return ca & cb
            if opc == PcodeOp.INT_OR:  return ca | cb
            if opc == PcodeOp.INT_XOR: return ca ^ cb

        break
    return None

def stack_var_from_arg(arg_vn, hf):
    if arg_vn is None or hf is None:
        return None
    base_vn, add_off = peel_varnode(arg_vn)

    # Prefer HighVariable symbol
    try:
        high = base_vn.getHigh() if base_vn else None
        if high:
            sym = high.getSymbol()
            if sym and is_stack_storage(sym):
                try:
                    dt = high.getDataType()
                    size = dt.getLength() if dt else sym.getSize()
                except Exception:
                    size = sym.getSize()
                return (sym.getName(), int(size) if size is not None else None, int(add_off))
    except Exception:
        pass

    # Fallback: match stack offset to local symbol storage
    try:
        if base_vn and base_vn.isAddress():
            a = base_vn.getAddress()
            if a and a.getAddressSpace() and a.getAddressSpace().isStackSpace():
                stack_off = int(a.getOffset()) + int(add_off)
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
                                    lo = o
                                    hi = o + sz
                                    min_off = lo if min_off is None else min(min_off, lo)
                                    max_off = hi if max_off is None else max(max_off, hi)
                            if min_off is not None and max_off is not None:
                                if min_off <= stack_off < max_off:
                                    return (sym.getName(), int(sym.getSize()), int(stack_off - min_off))
                        except Exception:
                            continue
    except Exception:
        pass

    return None

def called_name_from_instruction(callsite_addr):
    """
    Extremely reliable for direct calls:
      instruction.getFlows() yields the call destination.
    For indirect calls, returns None.
    """
    try:
        ins = currentProgram.getListing().getInstructionAt(callsite_addr)
        if not ins:
            return None
        flows = ins.getFlows()
        if not flows or len(flows) == 0:
            return None
        dst = flows[0]
        if dst is None:
            return None
        fm = currentProgram.getFunctionManager()
        f = fm.getFunctionAt(dst)
        if f:
            return f.getName()
        sym = currentProgram.getSymbolTable().getPrimarySymbol(dst)
        return sym.getName() if sym else None
    except Exception:
        return None

class StackOverflowStep1b:
    def __init__(self):
        self.decomp = DecompInterface()
        self.decomp.openProgram(currentProgram)
        self.findings = []
        self.call_hist = Counter()

    def resolve_call_target_name(self, call_op):
        """
        Best-effort resolution:
          1) derive from listing instruction flows (best for direct calls)
          2) decompiler target varnode (address/constant/high symbol)
        """
        try:
            addr = call_op.getSeqnum().getTarget()
            name = called_name_from_instruction(addr)
            if name:
                return name

            # fallback: decompiler target vn
            if call_op.getNumInputs() < 1:
                return None
            tgt = call_op.getInput(0)
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

        if not (CONFIG["emit_bookmarks"] or CONFIG["emit_comments"]):
            return

        paddr = addr
        if hasattr(paddr, 'getPhysicalAddress'):
            paddr = paddr.getPhysicalAddress()

        if CONFIG["emit_bookmarks"]:
            try:
                bm = currentProgram.getBookmarkManager()
                bm.setBookmark(paddr, "Analysis", f"[{severity}] {vuln_type}", details[:120])
            except Exception:
                pass

        if CONFIG["emit_comments"]:
            try:
                listing = currentProgram.getListing()
                cu = listing.getCodeUnitAt(paddr)
                if cu:
                    plate = f">>> VULN: {vuln_type} [{severity}] <<<\n{details}"
                    existing = cu.getComment(CodeUnit.PLATE_COMMENT)
                    if existing and vuln_type not in existing:
                        plate = existing + "\n" + plate
                    elif existing:
                        plate = existing
                    cu.setComment(CodeUnit.PLATE_COMMENT, plate)
                    cu.setComment(CodeUnit.EOL_COMMENT, f"[!] {severity} - {vuln_type}")
            except Exception:
                pass

    def analyze_function(self, func):
        res = self.decomp.decompileFunction(func, CONFIG["decompile_timeout_s"], TaskMonitor.DUMMY)
        if not res.decompileCompleted():
            return (0, 0, 0)

        hf = res.getHighFunction()
        if hf is None:
            return (0, 0, 0)

        calls_seen = 0
        calls_named = 0
        sink_hits = 0

        it = hf.getPcodeOps()
        while it.hasNext():
            op = it.next()
            opc = op.getOpcode()
            if opc not in (PcodeOp.CALL, PcodeOp.CALLIND):
                continue

            calls_seen += 1
            addr = op.getSeqnum().getTarget()

            raw = self.resolve_call_target_name(op)
            norm = normalize_func_name(raw)
            if norm:
                calls_named += 1
                self.call_hist[norm] += 1

            # --- Unbounded sinks (dst only) ---
            if norm in UNBOUNDED_SINKS:
                dst_idx = UNBOUNDED_SINKS[norm]
                if op.getNumInputs() <= 1 + dst_idx:
                    continue
                dst_vn = op.getInput(1 + dst_idx)
                sv = stack_var_from_arg(dst_vn, hf)
                if not sv:
                    continue
                var_name, var_size, var_off = sv
                rem = None if var_size is None else max(0, int(var_size) - int(var_off))
                size_str = f"[{var_size}]" if var_size is not None else ""
                off_str  = f"+{var_off}" if var_off else ""
                details = f"{norm}(dst={var_name}{size_str}{off_str}) - unbounded write into stack buffer"
                self.add_finding(func.getName(), addr, "STACK_OVERFLOW_UNBOUNDED", "HIGH", details)
                sink_hits += 1
                continue

            # --- Bounded length sinks (dst + len) ---
            if norm in BOUNDED_LEN_SINKS:
                dst_idx, len_idx = BOUNDED_LEN_SINKS[norm]
                if op.getNumInputs() <= 1 + max(dst_idx, len_idx):
                    continue

                dst_vn = op.getInput(1 + dst_idx)
                len_vn = op.getInput(1 + len_idx)

                sv = stack_var_from_arg(dst_vn, hf)
                if not sv:
                    continue
                var_name, var_size, var_off = sv
                if var_size is None:
                    # unknown buffer size => still a candidate but lower confidence
                    details = f"{norm}(dst={var_name}+{var_off}, len=?) - bounded API but dst size unknown"
                    self.add_finding(func.getName(), addr, "STACK_OVERFLOW_BOUNDED_CANDIDATE", "MEDIUM", details)
                    sink_hits += 1
                    continue

                rem = max(0, int(var_size) - int(var_off))
                n = eval_const_int(len_vn)

                if n is None:
                    details = f"{norm}(dst={var_name}[{var_size}]+{var_off}, len=non-const) - possible overflow (len not constant)"
                    self.add_finding(func.getName(), addr, "STACK_OVERFLOW_BOUNDED_CANDIDATE", "MEDIUM", details)
                    sink_hits += 1
                    continue

                if n > rem:
                    details = f"{norm}(dst={var_name}[{var_size}]+{var_off}, len={n}) - definite overflow (len > remaining {rem})"
                    self.add_finding(func.getName(), addr, "STACK_OVERFLOW_BOUNDED_DEFINITE", "HIGH", details)
                    sink_hits += 1
                else:
                    # Proven safe for this callsite (at least vs the local's recovered size)
                    if CONFIG["debug"]:
                        print(f"[safe] {func.getName()} {addr}: {norm} len={n} <= rem={rem}")

        return (calls_seen, calls_named, sink_hits)

    def run(self):
        print("=" * 70)
        print(" TG MemCorr Detector - Step 1b (memcpy/strncpy stack overflow)")
        print("=" * 70)

        funcs = list(currentProgram.getFunctionManager().getFunctions(True))
        if CONFIG["max_funcs"] is not None:
            funcs = funcs[: int(CONFIG["max_funcs"])]

        total_seen = total_named = total_sinks = 0

        for f in funcs:
            if f.isThunk() or f.isExternal():
                continue
            seen, named, sinks = self.analyze_function(f)
            total_seen += seen
            total_named += named
            total_sinks += sinks

        print(f"[*] Calls seen: {total_seen} | named: {total_named}")
        print(f"[*] Stack sink hits: {total_sinks}")
        print(f"[*] Findings: {len(self.findings)}")

        # Print call histogram for debugging
        if CONFIG["print_top_calls"] and len(self.call_hist):
            print("\n[*] Top normalized call targets:")
            for name, cnt in self.call_hist.most_common(int(CONFIG["print_top_calls"])):
                print(f"    {name}: {cnt}")

        try:
            out_path = os.path.join(os.path.expanduser("~"), "memcorr_step1b_stack_overflow.json")
            with open(out_path, "w") as fp:
                json.dump({
                    "findings": self.findings,
                    "config": CONFIG,
                    "top_calls": self.call_hist.most_common(200),
                }, fp, indent=2)
            print(f"[*] Results: {out_path}")
        except Exception:
            pass

def run():
    StackOverflowStep1b().run()

run()
