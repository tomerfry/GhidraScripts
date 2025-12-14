# TG MemCorr Detector - Step 1c2 (Fortified snprintf/vsnprintf stack writes)
# @category Security.TG
# @runtime PyGhidra
#
# Goal: make fortified and non-fortified formatted-write sinks actually produce findings,
#       even when the destination pointer is represented as:
#         - a STACK-space varnode, or
#         - a UNIQUE varnode defined by PTRSUB(stack_reg, const), or
#         - stack_local + variable_offset (PTRADD)
#
# Key fix vs prior step1c:
#   stack-destination detection now recognizes PTRSUB-based stack references, which are
#   common in High Pcode and are explicitly called out by Ghidra devs as a gotcha.

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import CodeUnit
import json, os
from collections import defaultdict

# Optional Swing prompts (GUI only)
try:
    from javax.swing import JOptionPane
    _HAS_SWING = True
except Exception:
    _HAS_SWING = False

CONFIG = {
    "interactive_external_tagging": True,
    "external_overrides_path": os.path.join(os.path.expanduser("~"), "tg_memcorr_external_overrides.json"),
    "max_expr_depth": 18,
    "flag_const_minus_var_size": True,
    "emit_low_confidence": True,
}

# Known sinks for this step (you can extend this table later)
KNOWN_EXTERNALS = {
    # Fortified glibc
    "__snprintf_chk":  {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": 3, "MAXLEN_ARG": 1}},
    "___snprintf_chk": {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": 3, "MAXLEN_ARG": 1}},
    "__vsnprintf_chk": {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": 3, "MAXLEN_ARG": 1}},
    "___vsnprintf_chk": {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": 3, "MAXLEN_ARG": 1}},
    "__sprintf_chk":   {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": None}},  # unbounded
    "___sprintf_chk":  {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": None}},

    # Non-fortified
    "snprintf":  {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": 3, "MAXLEN_ARG": 1}},
    "vsnprintf": {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": 1}},
    "sprintf":   {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": None}},  # unbounded
}

def _safe_get_stack_space_name():
    try:
        return currentProgram.getAddressFactory().getStackSpace().getName()
    except Exception:
        return "stack"

_STACK_SPACE_NAME = _safe_get_stack_space_name().lower()

class ExternalFunctionDB:
    def __init__(self, internal_names):
        self.base = dict(KNOWN_EXTERNALS)
        self.internal_names = set(internal_names)
        self.override_path = CONFIG["external_overrides_path"]
        self.overrides = self._load_overrides()

    def _load_overrides(self):
        try:
            if os.path.exists(self.override_path):
                with open(self.override_path, "r") as fp:
                    data = json.load(fp)
                    if isinstance(data, dict):
                        return data
        except Exception:
            pass
        return {}

    def _save_overrides(self):
        try:
            with open(self.override_path, "w") as fp:
                json.dump(self.overrides, fp, indent=2, sort_keys=True)
        except Exception:
            pass

    def normalize(self, name):
        if not name:
            return None
        n = name
        if n.startswith("PTR_"):
            parts = n[4:].rsplit("_", 1)
            if parts:
                n = parts[0]
        n = n.lstrip("_")
        # common fortify suffix
        if n.endswith("_chk"):
            n = n[:-4] + "_chk"  # keep _chk token so caller can decide
        # normalize triple underscore artifacts sometimes seen
        n = n.replace("___", "__")
        # collapse leading __
        while n.startswith("__"):
            n = n[2:]
        return n

    def get(self, name):
        n = self.normalize(name) or name
        if name in self.overrides:
            return self.overrides[name], name
        if n in self.overrides:
            return self.overrides[n], n

        if name in self.base:
            return self.base[name], name
        if n in self.base:
            return self.base[n], n
        return None, n

    def maybe_prompt_for_unknown(self, norm_name, is_external):
        # Only prompt for true externals; do not spam on internal/user functions.
        if not CONFIG["interactive_external_tagging"]:
            return
        if not is_external:
            return
        if not norm_name:
            return
        if norm_name in self.internal_names:
            return
        if norm_name in self.base or norm_name in self.overrides:
            return

        if not _HAS_SWING:
            # Headless: don't block; just emit a hint.
            print("[TG_MEMCORR] Unknown external '{}' (no GUI prompt available).".format(norm_name))
            print("            Add to overrides JSON if you want to treat it as a sink.")
            return

        options = [
            "Ignore",
            "Stack write sink (snprintf_chk-like: dst,arg0 | len,arg3)",
            "Stack write sink (sprintf-like: dst,arg0 | unbounded)",
        ]
        msg = "Unknown external encountered:\n\n{}\n\nTag it for analysis?".format(norm_name)
        choice = JOptionPane.showOptionDialog(
            None, msg, "TG MemCorr: Tag external",
            JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
            None, options, options[0]
        )
        if choice == 0 or choice == JOptionPane.CLOSED_OPTION:
            self.overrides[norm_name] = {"traits": ["IGNORE"], "params": {}}
            self._save_overrides()
            return
        if choice == 1:
            self.overrides[norm_name] = {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": 1}}
            self._save_overrides()
            return
        if choice == 2:
            self.overrides[norm_name] = {"traits": ["STACK_WRITE_SINK"], "params": {"DST_ARG": 0, "SIZE_ARG": None}}
            self._save_overrides()
            return


class DetectorStep1c2:
    def __init__(self):
        self.decomp = DecompInterface()
        self.decomp.openProgram(currentProgram)

        self.findings = []
        self.seen_calls = 0
        self.named_calls = 0
        self.sink_hits = 0
        self.call_hist = defaultdict(int)

        # internal function name set
        self.internal_names = set()
        for f in currentProgram.getFunctionManager().getFunctions(True):
            try:
                if not f.isExternal():
                    self.internal_names.add(f.getName())
            except Exception:
                pass

        self.extern_db = ExternalFunctionDB(self.internal_names)

        self.thunk_map = {}
        self.got_map = {}
        self._build_call_maps()

    def _build_call_maps(self):
        for func in currentProgram.getFunctionManager().getFunctions(True):
            try:
                if func.isThunk():
                    thunked = func.getThunkedFunction(False)
                    if thunked:
                        self.thunk_map[func.getEntryPoint()] = thunked.getName()
                        self.thunk_map[func.getName()] = thunked.getName()
            except Exception:
                pass

        for sym in currentProgram.getSymbolTable().getAllSymbols(True):
            try:
                name = sym.getName()
                if name.startswith("PTR_"):
                    parts = name[4:].rsplit("_", 1)
                    if parts:
                        self.got_map[sym.getAddress()] = parts[0]
                        self.got_map[name] = parts[0]
            except Exception:
                pass

    def _resolve_indirect(self, vn, depth):
        if depth > 6 or not vn:
            return None
        hi = vn.getHigh()
        if hi and hi.getSymbol():
            nm = hi.getSymbol().getName()
            if nm in self.got_map:
                return self.got_map[nm]
            if nm.startswith("PTR_"):
                return nm[4:].rsplit("_", 1)[0]

        d = vn.getDef()
        if not d:
            return None
        opc = d.getOpcode()
        if opc == PcodeOp.LOAD:
            ptr = d.getInput(1)
            if ptr:
                hi2 = ptr.getHigh()
                if hi2 and hi2.getSymbol():
                    nm2 = hi2.getSymbol().getName()
                    if nm2.startswith("PTR_"):
                        return nm2[4:].rsplit("_", 1)[0]
            return self._resolve_indirect(ptr, depth + 1)
        if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.PTRSUB, PcodeOp.PTRADD):
            return self._resolve_indirect(d.getInput(0), depth + 1)
        return None

    def resolve_call_target(self, call_op):
        """
        Returns (name, target_addr, is_external)
        """
        if call_op.getNumInputs() < 1:
            return None, None, False
        tgt = call_op.getInput(0)
        if not tgt:
            return None, None, False

        listing = currentProgram.getListing()

        # direct address varnode
        if tgt.isAddress():
            a = tgt.getAddress()
            nm = None
            if a in self.thunk_map:
                nm = self.thunk_map[a]
            else:
                f = listing.getFunctionAt(a)
                if f:
                    nm = self.thunk_map.get(f.getName(), f.getName())
            if nm:
                f2 = listing.getFunctionAt(a)
                is_ext = bool(f2 and f2.isExternal())
                return nm, a, is_ext

        # constant -> address
        if tgt.isConstant():
            av = tgt.getOffset()
            try:
                a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(av)
                f = listing.getFunctionAt(a)
                if f:
                    return f.getName(), a, bool(f.isExternal())
            except Exception:
                pass

        # indirect
        nm = self._resolve_indirect(tgt, 0)
        if nm:
            return nm, None, True  # treat indirect as external-ish; it is not an internal callee we can prove
        return None, None, False

    # ---------- expression / stack helpers ----------
    def _peel(self, vn, depth=0):
        cur = vn
        d = 0
        while cur and d < depth:
            op = cur.getDef()
            if not op:
                break
            opc = op.getOpcode()
            if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE):
                cur = op.getInput(0)
                d += 1
                continue
            break
        return cur

    def vn_to_str(self, vn, depth=0):
        if not vn:
            return "?"
        if depth > 6:
            return "..."
        try:
            if vn.isConstant():
                return hex(vn.getOffset())
            if vn.isAddress():
                return str(vn.getAddress())
        except Exception:
            pass
        hi = vn.getHigh()
        if hi and hi.getSymbol():
            return hi.getSymbol().getName()
        d = vn.getDef()
        if not d:
            return "vn"
        opc = d.getOpcode()
        if opc == PcodeOp.INT_SUB:
            return "({} - {})".format(self.vn_to_str(d.getInput(0), depth+1), self.vn_to_str(d.getInput(1), depth+1))
        if opc == PcodeOp.INT_ADD:
            return "({} + {})".format(self.vn_to_str(d.getInput(0), depth+1), self.vn_to_str(d.getInput(1), depth+1))
        if opc == PcodeOp.PTRADD:
            return "PTRADD({}, {}, {})".format(self.vn_to_str(d.getInput(0), depth+1), self.vn_to_str(d.getInput(1), depth+1), self.vn_to_str(d.getInput(2), depth+1))
        if opc == PcodeOp.PTRSUB:
            return "PTRSUB({}, {})".format(self.vn_to_str(d.getInput(0), depth+1), self.vn_to_str(d.getInput(1), depth+1))
        return "op{}".format(opc)

    def is_const_minus_var(self, vn):
        """
        Recognize size expressions like CONST - var (typical underflow bug pattern).
        Return (True,const_val,var_vn) else (False,0,None)
        """
        if not vn:
            return (False, 0, None)
        vn = self._peel(vn, 2)
        d = vn.getDef()
        if not d:
            return (False, 0, None)
        if d.getOpcode() != PcodeOp.INT_SUB:
            return (False, 0, None)
        a = self._peel(d.getInput(0), 2)
        b = self._peel(d.getInput(1), 2)
        try:
            if a and a.isConstant() and b and (not b.isConstant()):
                return (True, a.getOffset(), b)
        except Exception:
            pass
        return (False, 0, None)

    def _addr_space_is_stack(self, vn):
        try:
            a = vn.getAddress()
            sp = a.getAddressSpace()
            return sp and (sp.isStackSpace() or sp.getName().lower() == _STACK_SPACE_NAME)
        except Exception:
            return False

    def _find_local_by_stack_off(self, hf, off):
        """
        Map a stack offset to a local symbol name/size if possible.
        """
        try:
            lsm = hf.getLocalSymbolMap()
            if not lsm:
                return None, None
            for sym in lsm.getSymbols():
                try:
                    st = sym.getStorage()
                    if st and st.isStackStorage():
                        base = st.getStackOffset()
                        sz = sym.getSize()
                        # storage usually references the first byte; allow range match
                        if base <= off < (base + max(1, sz)):
                            return sym.getName(), sz
                except Exception:
                    pass
        except Exception:
            pass
        return None, None

    def get_stack_dest_info(self, dst_vn, hf):
        """
        Return (is_stack, name, size, stack_off) for destination pointers.
        Works for:
          - local symbol varnode
          - stack-space address varnode
          - UNIQUE varnode defined by PTRSUB(stack_reg, const_off)
          - (base + off) where base resolves to any of the above
        """
        if not dst_vn:
            return (False, None, None, None)

        # 1) HighVariable symbol with stack storage (best case)
        try:
            hi = dst_vn.getHigh()
            if hi and hi.getSymbol():
                sym = hi.getSymbol()
                st = sym.getStorage()
                if st and st.isStackStorage():
                    nm = sym.getName()
                    try:
                        dt = hi.getDataType()
                        sz = dt.getLength() if dt else None
                    except Exception:
                        sz = None
                    return (True, nm, sz, st.getStackOffset())
        except Exception:
            pass

        # 2) Walk pointer-expression: accumulate constant offsets; detect PTRSUB(stack_reg, const)
        cur = dst_vn
        depth = 0
        const_off = 0
        stack_off = None

        while cur and depth < CONFIG["max_expr_depth"]:
            # direct stack address space varnode
            if self._addr_space_is_stack(cur):
                try:
                    stack_off = cur.getAddress().getOffset()
                except Exception:
                    stack_off = None
                nm, sz = (None, None)
                if stack_off is not None:
                    nm, sz = self._find_local_by_stack_off(hf, stack_off)
                return (True, nm or ("stack{}".format(hex(stack_off)) if stack_off is not None else "stack"), sz, stack_off)

            d = cur.getDef()
            if not d:
                break
            opc = d.getOpcode()

            # PTRSUB(sp, const)  => stack reference at const offset
            if opc == PcodeOp.PTRSUB:
                base = d.getInput(0)
                off_vn = d.getInput(1)
                off_c = None
                try:
                    if off_vn and off_vn.isConstant():
                        off_c = off_vn.getOffset()
                except Exception:
                    off_c = None

                # If base is stack pointer register, treat as stack reference.
                # (We don't rely on its name; the pattern itself is sufficient.)
                if off_c is not None and base and base.isRegister():
                    stack_off = off_c + const_off
                    nm, sz = self._find_local_by_stack_off(hf, stack_off)
                    return (True, nm or ("stack{}".format(hex(stack_off))), sz, stack_off)

                # otherwise, continue walking base
                if off_c is not None:
                    const_off += off_c
                cur = base
                depth += 1
                continue

            # PTRADD(base, idx, elsize) => base + idx*elsize, if idx constant
            if opc == PcodeOp.PTRADD:
                base = d.getInput(0)
                idx = d.getInput(1)
                elsz = d.getInput(2)
                try:
                    if idx and idx.isConstant() and elsz and elsz.isConstant():
                        const_off += idx.getOffset() * elsz.getOffset()
                except Exception:
                    pass
                cur = base
                depth += 1
                continue

            # INT_ADD/INT_SUB on pointers occasionally shows up
            if opc == PcodeOp.INT_ADD:
                a = d.getInput(0)
                b = d.getInput(1)
                try:
                    if b and b.isConstant():
                        const_off += b.getOffset()
                        cur = a
                        depth += 1
                        continue
                    if a and a.isConstant():
                        const_off += a.getOffset()
                        cur = b
                        depth += 1
                        continue
                except Exception:
                    pass
                break
            if opc == PcodeOp.INT_SUB:
                a = d.getInput(0)
                b = d.getInput(1)
                try:
                    if b and b.isConstant():
                        const_off -= b.getOffset()
                        cur = a
                        depth += 1
                        continue
                except Exception:
                    pass
                break

            if opc in (PcodeOp.COPY, PcodeOp.CAST):
                cur = d.getInput(0)
                depth += 1
                continue

            break

        # 3) final attempt: if we got a constant stack offset, map it
        if stack_off is not None:
            nm, sz = self._find_local_by_stack_off(hf, stack_off)
            return (True, nm or ("stack{}".format(hex(stack_off))), sz, stack_off)

        return (False, None, None, None)

    # ---------- output ----------
    def _add_finding(self, func_name, addr, ftype, severity, details):
        key = (func_name, str(addr), ftype)
        for f in self.findings:
            if (f["func"], f["addr"], f["type"]) == key:
                return

        self.findings.append({
            "func": func_name,
            "addr": str(addr),
            "type": ftype,
            "severity": severity,
            "details": details
        })

        # Bookmark + comments
        try:
            bm = currentProgram.getBookmarkManager()
            bm.setBookmark(addr, "Analysis", "[TG_MEMCORR] {} {}".format(severity, ftype), details[:120])
        except Exception:
            pass
        try:
            cu = currentProgram.getListing().getCodeUnitAt(addr)
            if cu:
                plate = ">>> TG_MEMCORR: {} [{}] <<<\n{}".format(ftype, severity, details)
                existing = cu.getComment(CodeUnit.PLATE_COMMENT)
                if existing and ftype not in existing:
                    plate = existing + "\n" + plate
                elif existing:
                    plate = existing
                cu.setComment(CodeUnit.PLATE_COMMENT, plate)
                cu.setComment(CodeUnit.EOL_COMMENT, "[TG_MEMCORR] {} {}".format(severity, ftype))
        except Exception:
            pass

    # ---------- analysis ----------
    def analyze_function(self, func):
        res = self.decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
        if not res or not res.decompileCompleted():
            return
        hf = res.getHighFunction()
        if not hf:
            return

        for op in hf.getPcodeOps():
            opc = op.getOpcode()
            if opc not in (PcodeOp.CALL, PcodeOp.CALLIND):
                continue

            self.seen_calls += 1
            call_name, tgt_addr, is_ext = self.resolve_call_target(op)
            if not call_name:
                continue
            self.named_calls += 1

            info, norm = self.extern_db.get(call_name)
            # prompt for unknown externals *before* fetching again
            self.extern_db.maybe_prompt_for_unknown(norm, is_ext)
            info, norm2 = self.extern_db.get(call_name)
            if not info:
                continue
            if "IGNORE" in info.get("traits", []):
                continue

            self.call_hist[norm2 or call_name] += 1

            if "STACK_WRITE_SINK" not in info.get("traits", []):
                continue

            params = info.get("params", {})
            dst_idx = params.get("DST_ARG", 0)
            size_idx = params.get("SIZE_ARG", None)

            # Pcode CALL inputs: [0]=target, [1]=arg0, [2]=arg1, ...
            if op.getNumInputs() <= dst_idx + 1:
                continue

            dst_vn = op.getInput(dst_idx + 1)
            is_stack, sym_name, sym_sz, stack_off = self.get_stack_dest_info(dst_vn, hf)
            if not is_stack:
                continue

            self.sink_hits += 1

            # Unbounded sink (sprintf-style)
            if size_idx is None:
                details = "{} writes into stack dest {} | dst={}".format(
                    norm2 or call_name,
                    sym_name or ("stack{}".format(hex(stack_off)) if stack_off is not None else "stack"),
                    self.vn_to_str(dst_vn),
                )
                self._add_finding(func.getName(), op.getSeqnum().getTarget(),
                                  "STACK_WRITE_UNBOUNDED", "HIGH", details)
                continue

            if op.getNumInputs() <= size_idx + 1:
                continue
            size_vn = op.getInput(size_idx + 1)

            
            # Optional: for fortified *_chk, also sanity-check LEN against MAXLEN when MAXLEN is known.
            maxlen_idx = params.get("MAXLEN_ARG", None)
            if maxlen_idx is not None and op.getNumInputs() > maxlen_idx + 1:
                maxlen_vn = op.getInput(maxlen_idx + 1)
                try:
                    if maxlen_vn and maxlen_vn.isConstant():
                        maxlen_c = maxlen_vn.getOffset()
                        # If LEN is constant and exceeds MAXLEN, that's a clear overflow request.
                        try:
                            if size_vn and size_vn.isConstant() and size_vn.getOffset() > maxlen_c:
                                details = "{} requests len={} > maxlen={} for stack dest {}".format(
                                    norm2 or call_name, size_vn.getOffset(), maxlen_c,
                                    sym_name or ("stack{}".format(hex(stack_off)) if stack_off is not None else "stack")
                                )
                                self._add_finding(func.getName(), op.getSeqnum().getTarget(),
                                                  "STACK_WRITE_LEN_GT_MAXLEN", "HIGH", details)
                        except Exception:
                            pass
                except Exception:
                    pass

# Pattern 1: CONST - VAR  (classic size underflow -> huge size)
            underflow, const_val, sub_vn = self.is_const_minus_var(size_vn)
            if CONFIG["flag_const_minus_var_size"] and underflow:
                details = "{} writes into stack buffer {} with size expr {} (CONST={} - VAR={})".format(
                    norm2 or call_name,
                    sym_name or ("stack{}".format(hex(stack_off)) if stack_off is not None else "stack"),
                    self.vn_to_str(size_vn),
                    hex(const_val),
                    self.vn_to_str(sub_vn),
                )
                if sym_sz:
                    details += " | stack_buf_size={}".format(sym_sz)
                details += " | Heuristic: CONST-VAR may underflow -> huge size -> overflow"
                self._add_finding(func.getName(), op.getSeqnum().getTarget(),
                                  "STACK_WRITE_SIZE_UNDERFLOW", "HIGH", details)
                continue

            # Pattern 2: constant size: compare against known stack object size
            try:
                if size_vn.isConstant():
                    szc = size_vn.getOffset()
                    if sym_sz and szc > sym_sz:
                        details = "{} writes {} bytes into stack buffer {} (buf_size={})".format(
                            norm2 or call_name, szc, sym_name, sym_sz
                        )
                        self._add_finding(func.getName(), op.getSeqnum().getTarget(),
                                          "STACK_WRITE_CONST_GT_BUFSZ", "HIGH", details)
                    elif CONFIG["emit_low_confidence"]:
                        details = "{} writes {} bytes into stack buffer {} (buf_size={})".format(
                            norm2 or call_name, szc, sym_name or "stack", sym_sz or "?"
                        )
                        self._add_finding(func.getName(), op.getSeqnum().getTarget(),
                                          "STACK_WRITE_CONST_SIZE", "LOW", details)
                    continue
            except Exception:
                pass

            # Pattern 3: non-constant size: candidate
            details = "{} writes into stack buffer {} with non-constant size {} | dst={}".format(
                norm2 or call_name,
                sym_name or ("stack{}".format(hex(stack_off)) if stack_off is not None else "stack"),
                self.vn_to_str(size_vn),
                self.vn_to_str(dst_vn),
            )
            if sym_sz:
                details += " | stack_buf_size={}".format(sym_sz)
            self._add_finding(func.getName(), op.getSeqnum().getTarget(),
                              "STACK_WRITE_NONCONST_SIZE", "MEDIUM", details)

    def run(self):
        print("=" * 70)
        print(" TG MemCorr Detector - Step 1c2 (Fortified snprintf/vsnprintf stack writes)")
        print("=" * 70)
        print("[*] Config: interactive_external_tagging={}, max_expr_depth={}".format(
            CONFIG["interactive_external_tagging"], CONFIG["max_expr_depth"]))
        print("[*] External override DB: {}".format(CONFIG["external_overrides_path"]))

        funcs = list(currentProgram.getFunctionManager().getFunctions(True))
        print("[*] Analyzing {} functions...".format(len(funcs)))

        for f in funcs:
            try:
                if f.isThunk() or f.isExternal():
                    continue
            except Exception:
                pass
            self.analyze_function(f)

        print("\n[*] Calls seen: {} | named: {}".format(self.seen_calls, self.named_calls))
        print("[*] Stack-write sinks hit: {}".format(self.sink_hits))
        print("[*] Findings: {}".format(len(self.findings)))

        if self.call_hist:
            print("\n[*] Top normalized call targets:")
            for k, v in sorted(self.call_hist.items(), key=lambda kv: -kv[1])[:25]:
                print("    {}: {}".format(k, v))

        out_path = os.path.join(os.path.expanduser("~"), "memcorr_step1c2_fortified_stack_writes.json")
        try:
            with open(out_path, "w") as fp:
                json.dump({"findings": self.findings, "config": CONFIG}, fp, indent=2)
            print("[*] Results: {}".format(out_path))
        except Exception:
            pass

        return self.findings


def run():
    det = DetectorStep1c2()
    det.run()

run()
