# TG MemCorr Detector - Step 2a2 (Integer overflow in allocation size) - refined
# @category Security
# @runtime PyGhidra
#
# Improvements vs Step 2a:
#   - Integrates external override DB (same format as earlier steps) to handle unknown alloc wrappers.
#   - Reduces false positives for "small-width + constant" patterns (e.g., ushort + 0x13) on 64-bit/32-bit size_t.
#   - Computes size_t bit-width from program pointer size (still allows optional 32-bit heuristic).
#   - Flags true high-risk patterns: MUL/SHIFT involving attacker-influenced values, truncation/narrowing, CONST-VAR underflow.
#
# Output:
#   Bookmarks + comments + JSON under %USERPROFILE% (home dir).

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import CodeUnit
from collections import Counter
import json, os

CONFIG = {
    "decompile_timeout_s": 60,
    "max_expr_depth": 32,
    "emit_bookmarks": True,
    "emit_comments": True,

    # If True, still emit a MEDIUM finding when we can prove "would overflow on 32-bit size_t",
    # even if the loaded binary is 64-bit. Useful when you review code that is reused cross-arch.
    "also_check_32bit_wrap": True,

    # Reduce noise: suppress "narrow + const" (e.g., uint16 + 0x13) if the result cannot overflow size_t.
    "suppress_smallwidth_plus_const": True,

    # Path to external overrides (traits-based DB used in earlier steps).
    "interactive_external_tagging": True,
    "external_overrides_path": os.path.join(os.path.expanduser("~"), "tg_memcorr_external_overrides.json"),
}

# Built-in allocation specs (you can extend interactively via override DB)
ALLOC_SPECS = {
    "malloc":  {"kind": "single", "size_args": [0]},
    "calloc":  {"kind": "mul",    "size_args": [0, 1]},  # nmemb, size
    "realloc": {"kind": "single", "size_args": [1]},
    "__libc_malloc": {"kind": "single", "size_args": [0]},
    "__libc_calloc": {"kind": "mul",    "size_args": [0, 1]},
    "__libc_realloc": {"kind": "single", "size_args": [1]},
}

ALIASES = {
    "__builtin_malloc": "malloc",
    "__builtin_calloc": "calloc",
    "__builtin_realloc": "realloc",
}

def _get_ptr_bits():
    # Best-effort. Fallback to 64.
    try:
        ps = int(currentProgram.getDefaultPointerSize())
        if ps in (4, 8):
            return ps * 8
    except Exception:
        pass
    return 64

SIZE_T_BITS = _get_ptr_bits()

def normalize_func_name(name):
    if not name:
        return None
    n = name

    # Decompiler may produce PTR_foo_00001234
    if n.startswith("PTR_"):
        rest = n[4:]
        parts = rest.rsplit("_", 1)
        if parts and parts[0]:
            n = parts[0]

    # Common import/thunk prefixes
    for pfx in ("imp.", "thunk_", "__imp_", "plt_", "j_"):
        if n.startswith(pfx):
            n = n[len(pfx):]

    # GLIBC version suffixes
    if "@@GLIBC" in n:
        n = n.split("@@GLIBC")[0]

    if "@plt" in n:
        n = n.replace("@plt", "")
    if n.endswith(".plt"):
        n = n[:-4]

    # Keep __xxx (glibc internals) but normalize _foo -> foo
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

def resolve_callee_name_from_instruction(call_addr):
    try:
        ins = currentProgram.getListing().getInstructionAt(call_addr)
        if not ins:
            return None
        flows = ins.getFlows()
        if flows and len(flows) > 0:
            dst = flows[0]
            fm = currentProgram.getFunctionManager()
            f = fm.getFunctionAt(dst)
            if f:
                f = canonical_function(f)
                return f.getName()
            sym = currentProgram.getSymbolTable().getPrimarySymbol(dst)
            return sym.getName() if sym else None
    except Exception:
        pass
    return None

def resolve_callee_name_from_pcode(op):
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
                f = canonical_function(f)
                return f.getName()
        if tgt.isConstant():
            a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(tgt.getOffset())
            f = fm.getFunctionAt(a)
            if f:
                f = canonical_function(f)
                return f.getName()
        high = tgt.getHigh()
        if high and high.getSymbol():
            return high.getSymbol().getName()
    except Exception:
        pass
    return None

def vn_size_bits(vn):
    try:
        if vn is None:
            return None
        sz = vn.getSize()
        if sz and sz > 0:
            return int(sz) * 8
    except Exception:
        pass
    return None

def is_param_or_global(vn):
    if vn is None:
        return False
    try:
        high = vn.getHigh()
        if high and high.getSymbol():
            s = high.getSymbol()
            return bool(s.isParameter() or s.isGlobal())
    except Exception:
        pass
    return False

def expr_walk(vn, max_depth):
    """Yield (varnode, defop, depth)."""
    seen = set()
    stack = [(vn, 0)]
    while stack:
        cur, d = stack.pop()
        if cur is None or d > max_depth:
            continue
        try:
            cid = id(cur)
            if cid in seen:
                continue
            seen.add(cid)
        except Exception:
            pass
        defop = cur.getDef()
        yield cur, defop, d
        if not defop:
            continue
        for i in range(defop.getNumInputs()):
            stack.append((defop.getInput(i), d + 1))

def expr_contains_ops(vn, opcodes, max_depth=32):
    for _, defop, _ in expr_walk(vn, max_depth):
        if defop and defop.getOpcode() in opcodes:
            return True
    return False

def expr_has_truncation(vn, max_depth=24):
    # SUBPIECE/PIECE is the common one. Also treat "copy into smaller varnode" as truncation.
    if expr_contains_ops(vn, {PcodeOp.SUBPIECE, PcodeOp.PIECE}, max_depth=max_depth):
        return True
    # Heuristic: if there is a SUBPIECE anywhere or if sizes shrink across CAST/COPY chains.
    try:
        base_bits = vn_size_bits(vn)
        if base_bits is None:
            return False
        for cur, defop, _ in expr_walk(vn, max_depth):
            if not defop:
                continue
            opc = defop.getOpcode()
            if opc in (PcodeOp.CAST, PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
                in0 = defop.getInput(0)
                if in0 is None:
                    continue
                in_bits = vn_size_bits(in0)
                out_bits = vn_size_bits(cur)
                if in_bits and out_bits and out_bits < in_bits:
                    return True
    except Exception:
        pass
    return False

def eval_const_u64(vn, max_depth=12):
    if vn is None:
        return None
    try:
        if vn.isConstant():
            return int(vn.getOffset()) & ((1<<64)-1)
    except Exception:
        return None
    cur = vn
    depth = 0
    while cur is not None and depth < max_depth:
        depth += 1
        d = cur.getDef()
        if not d:
            return None
        opc = d.getOpcode()
        if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.SUBPIECE, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            cur = d.getInput(0)
            try:
                if cur and cur.isConstant():
                    return int(cur.getOffset()) & ((1<<64)-1)
            except Exception:
                return None
            continue
        if opc in (PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, PcodeOp.INT_LEFT):
            a = eval_const_u64(d.getInput(0), 6)
            b = eval_const_u64(d.getInput(1), 6)
            if a is None or b is None:
                return None
            if opc == PcodeOp.INT_ADD:
                return (a + b) & ((1<<64)-1)
            if opc == PcodeOp.INT_SUB:
                return (a - b) & ((1<<64)-1)
            if opc == PcodeOp.INT_MULT:
                return (a * b) & ((1<<64)-1)
            if opc == PcodeOp.INT_LEFT:
                return (a << b) & ((1<<64)-1)
        return None
    return None

def is_smallwidth_plus_smallconst(size_vn):
    """True if expression is basically (small-width var) + small const, and cannot overflow size_t."""
    if size_vn is None:
        return False
    d = size_vn.getDef()
    if not d or d.getOpcode() not in (PcodeOp.INT_ADD,):
        return False
    a = d.getInput(0)
    b = d.getInput(1)
    ca = eval_const_u64(a, 8)
    cb = eval_const_u64(b, 8)
    # ensure one side is constant
    if (ca is None) == (cb is None):
        return False
    var = b if ca is not None else a
    cst = ca if ca is not None else cb
    vb = vn_size_bits(var)
    if vb is None:
        return False
    # require var width <= 16/32 and const small
    if vb <= 16 and cst <= 0x1000:
        return True
    if vb <= 32 and cst <= 0x1000 and SIZE_T_BITS >= 64:
        # on 64-bit size_t, uint32 + 0x13 won't overflow size_t
        return True
    return False

class ExternalOverrideDB:
    """
    Shared override format used in earlier steps:
      {
        "overrides": {
          "foo": {"traits":["ALLOC"], "params":{"ALLOC_SIZE":0}}
        }
      }
    We only care about ALLOC traits here.
    """
    def __init__(self, path):
        self.path = path
        self.db = {}
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.path):
                with open(self.path, "r") as fp:
                    j = json.load(fp)
                self.db = j.get("overrides", {}) if isinstance(j, dict) else {}
        except Exception:
            self.db = {}

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        except Exception:
            pass
        try:
            payload = {"overrides": self.db}
            with open(self.path, "w") as fp:
                json.dump(payload, fp, indent=2)
        except Exception:
            pass

    def get_alloc_spec(self, norm_name):
        e = self.db.get(norm_name)
        if not e:
            return None
        traits = set(e.get("traits", []))
        params = e.get("params", {})
        if "ALLOC" not in traits:
            return None
        # Support either ALLOC_SIZE (single) or (ALLOC_NMEMB, ALLOC_ELEM) for calloc-like
        if "ALLOC_NMEMB" in params and "ALLOC_ELEM" in params:
            return {"kind": "mul", "size_args": [int(params["ALLOC_NMEMB"]), int(params["ALLOC_ELEM"])]}
        if "ALLOC_SIZE" in params:
            return {"kind": "single", "size_args": [int(params["ALLOC_SIZE"])]}
        return {"kind": "single", "size_args": [0]}

    def maybe_tag_interactive(self, raw_name):
        if not CONFIG["interactive_external_tagging"]:
            return
        if not raw_name:
            return
        norm = normalize_func_name(raw_name)
        if not norm or norm in ALLOC_SPECS or norm in self.db:
            return
        # Prompt user once per unknown external
        try:
            ans = askChoice("TG MemCorr - External Tagging",
                            f"Unknown external '{raw_name}' (normalized '{norm}'). Tag as allocator?",
                            ["No", "malloc-like (single size arg)", "calloc-like (nmemb*size)", "Skip and don't ask again"],
                            "No")
            if ans == "malloc-like (single size arg)":
                self.db[norm] = {"traits": ["ALLOC"], "params": {"ALLOC_SIZE": 0}}
                self.save()
            elif ans == "calloc-like (nmemb*size)":
                self.db[norm] = {"traits": ["ALLOC"], "params": {"ALLOC_NMEMB": 0, "ALLOC_ELEM": 1}}
                self.save()
            elif ans == "Skip and don't ask again":
                self.db[norm] = {"traits": ["IGNORE"], "params": {}}
                self.save()
        except Exception:
            pass

class Detector:
    def __init__(self):
        self.decomp = DecompInterface()
        self.decomp.openProgram(currentProgram)
        self.findings = []
        self.calls_seen = 0
        self.named = 0
        self.by_target = Counter()
        self.ovr = ExternalOverrideDB(CONFIG["external_overrides_path"])

    def add_finding(self, func_name, addr, vuln_type, severity, details):
        self.findings.append({"func": func_name, "addr": str(addr), "type": vuln_type, "severity": severity, "details": details})
        paddr = addr
        if hasattr(paddr, "getPhysicalAddress"):
            paddr = paddr.getPhysicalAddress()

        if CONFIG["emit_bookmarks"]:
            try:
                currentProgram.getBookmarkManager().setBookmark(
                    paddr, "Analysis", f"[TG_MEMCORR] {severity} {vuln_type}", details[:160]
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

    def analyze_call(self, func, hf, op):
        self.calls_seen += 1
        addr = op.getSeqnum().getTarget()

        raw = resolve_callee_name_from_instruction(addr) or resolve_callee_name_from_pcode(op)
        if not raw:
            return
        self.named += 1

        # Allow user to tag unknown externals as alloc wrappers
        self.ovr.maybe_tag_interactive(raw)

        norm = normalize_func_name(raw)
        if not norm:
            return
        self.by_target[norm] += 1

        spec = ALLOC_SPECS.get(norm) or self.ovr.get_alloc_spec(norm)
        if not spec:
            return

        # CALL inputs: [0]=target, [1..]=args
        args = [op.getInput(i) for i in range(1, op.getNumInputs())]
        size_args = spec.get("size_args", [])
        if any(i >= len(args) for i in size_args):
            return

        kind = spec.get("kind", "single")

        if kind == "mul":
            a = args[size_args[0]]
            b = args[size_args[1]]
            ca = eval_const_u64(a); cb = eval_const_u64(b)

            influenced = is_param_or_global(a) or is_param_or_global(b)

            # Strong signals
            has_mul = expr_contains_ops(a, {PcodeOp.INT_MULT, PcodeOp.INT_LEFT}, CONFIG["max_expr_depth"]) or \
                      expr_contains_ops(b, {PcodeOp.INT_MULT, PcodeOp.INT_LEFT}, CONFIG["max_expr_depth"]) or \
                      expr_contains_ops(a, {PcodeOp.INT_ADD, PcodeOp.INT_SUB}, CONFIG["max_expr_depth"]) or \
                      expr_contains_ops(b, {PcodeOp.INT_ADD, PcodeOp.INT_SUB}, CONFIG["max_expr_depth"])

            trunc = expr_has_truncation(a) or expr_has_truncation(b)

            # Constant wrap checks
            if ca is not None and cb is not None:
                prod64 = (ca * cb) & ((1<<64)-1)
                # check native size_t
                if SIZE_T_BITS == 32 and prod64 > 0xffffffff:
                    self.add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC", "HIGH",
                                     f"calloc-like size calc: {ca:#x} * {cb:#x} = {prod64:#x} exceeds 32-bit size_t (native)")
                    return
                if CONFIG["also_check_32bit_wrap"] and prod64 > 0xffffffff and SIZE_T_BITS != 32:
                    self.add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC_CROSSARCH", "MEDIUM",
                                     f"calloc-like size calc: {ca:#x} * {cb:#x} = {prod64:#x} would wrap on 32-bit size_t (cross-arch heuristic)")
                    return

            if influenced and (has_mul or trunc):
                sev = "HIGH"
                why = []
                if influenced: why.append("param/global")
                if has_mul: why.append("arith/mul/shift")
                if trunc: why.append("truncation")
                self.add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC_CANDIDATE", sev,
                                 "calloc-like allocation size depends on {}. nmemb_expr={}, elem_expr={}".format(
                                     ", ".join(why), a, b))
            elif has_mul or trunc:
                self.add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC_CANDIDATE", "MEDIUM",
                                 f"calloc-like size uses arithmetic/truncation; review. nmemb_expr={a}, elem_expr={b}")
            return

        # single size
        size_vn = args[size_args[0]]
        c = eval_const_u64(size_vn)

        # Noise reduction: (small-width var + small const) is not an integer-overflow risk for size_t on 64-bit,
        # and is generally not a "wrap" risk on 32-bit unless var itself is already 32-bit and unchecked.
        if CONFIG["suppress_smallwidth_plus_const"] and is_smallwidth_plus_smallconst(size_vn) and not expr_has_truncation(size_vn):
            # Still allow if operand is param/global and size_t is 32-bit (could be large 32-bit var + const)
            # but our predicate already tries to avoid that by focusing on <=16 or <=32 on 64-bit.
            return

        influenced = is_param_or_global(size_vn)

        has_mul_or_shift = expr_contains_ops(size_vn, {PcodeOp.INT_MULT, PcodeOp.INT_LEFT}, CONFIG["max_expr_depth"])
        has_addsub = expr_contains_ops(size_vn, {PcodeOp.INT_ADD, PcodeOp.INT_SUB}, CONFIG["max_expr_depth"])
        trunc = expr_has_truncation(size_vn)

        # Constant wrap checks
        if c is not None:
            if SIZE_T_BITS == 32 and c > 0xffffffff:
                self.add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC", "HIGH",
                                 f"{norm} size constant {c:#x} exceeds 32-bit size_t (native)")
                return
            if CONFIG["also_check_32bit_wrap"] and SIZE_T_BITS != 32 and c > 0xffffffff:
                self.add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC_CROSSARCH", "LOW",
                                 f"{norm} size constant {c:#x} would not fit 32-bit size_t (cross-arch heuristic)")
                return

        # Underflow heuristic: CONST - VAR used as size (common bug)
        if expr_contains_ops(size_vn, {PcodeOp.INT_SUB}, CONFIG["max_expr_depth"]):
            # detect CONST - VAR at root if possible
            d = size_vn.getDef()
            if d and d.getOpcode() == PcodeOp.INT_SUB:
                a = d.getInput(0); b = d.getInput(1)
                if eval_const_u64(a) is not None and eval_const_u64(b) is None:
                    self.add_finding(func.getName(), addr, "ALLOC_SIZE_UNDERFLOW_CANDIDATE", "HIGH",
                                     f"{norm} size is CONST-VAR; may underflow to huge size. size_expr={size_vn}")
                    return

        # Severity decision
        if influenced and (has_mul_or_shift or trunc):
            self.add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC_CANDIDATE", "HIGH",
                             f"{norm} size depends on param/global and includes mul/shift or truncation. size_expr={size_vn}")
        elif influenced and has_addsub:
            self.add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC_CANDIDATE", "MEDIUM",
                             f"{norm} size depends on param/global and includes arithmetic. size_expr={size_vn}")
        elif has_mul_or_shift or trunc:
            self.add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC_CANDIDATE", "MEDIUM",
                             f"{norm} size includes mul/shift or truncation; review. size_expr={size_vn}")
        elif has_addsub:
            # keep as LOW to avoid noise
            self.add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC_CANDIDATE", "LOW",
                             f"{norm} size includes arithmetic; review if attacker-influenced. size_expr={size_vn}")

    def analyze_function(self, func):
        res = self.decomp.decompileFunction(func, CONFIG["decompile_timeout_s"], TaskMonitor.DUMMY)
        if not res.decompileCompleted():
            return
        hf = res.getHighFunction()
        if hf is None:
            return

        it = hf.getPcodeOps()
        while it.hasNext():
            op = it.next()
            if op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND):
                self.analyze_call(func, hf, op)

    def run(self):
        print("=" * 70)
        print(" TG MemCorr Detector - Step 2a2 (Integer overflow in allocation size) - refined")
        print("=" * 70)
        print(f"[*] size_t bits (heuristic): {SIZE_T_BITS}")
        print(f"[*] External override DB: {CONFIG['external_overrides_path']}")
        funcs = list(currentProgram.getFunctionManager().getFunctions(True))
        print(f"[*] Analyzing {len(funcs)} functions...\n")

        for f in funcs:
            if f.isThunk() or f.isExternal():
                continue
            self.analyze_function(f)

        print(f"[*] Calls seen: {self.calls_seen} | named: {self.named}")
        print(f"[*] Findings: {len(self.findings)}")
        if self.by_target:
            print("\n[*] Top normalized call targets:")
            for n, c in self.by_target.most_common(25):
                print(f"    {n}: {c}")

        out_path = os.path.join(os.path.expanduser('~'), 'memcorr_step2a2_integer_overflow_alloc.json')
        try:
            with open(out_path, "w") as fp:
                json.dump({"findings": self.findings, "config": CONFIG, "size_t_bits": SIZE_T_BITS}, fp, indent=2)
            print(f"[*] Results: {out_path}")
        except Exception:
            pass

def run():
    Detector().run()

run()
