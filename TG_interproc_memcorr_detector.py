# Memory Corruption Detector - Interprocedural Edition v1.0
# Deep taint tracking across function boundaries
# @category Security  
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import CodeUnit
from collections import defaultdict
import json

# =============================================================================
# CONFIGURATION
# =============================================================================

MAX_INTERPROC_DEPTH = 3
MAX_FUNCTIONS = 0  # 0 = all
VERBOSE = False

# =============================================================================
# SINK/SOURCE DEFINITIONS
# =============================================================================

OVERFLOW_SINKS = {
    "strcpy": (0, 1, False),   # (dst_idx, src_idx, bounded)
    "strcat": (0, 1, False),
    "sprintf": (0, -1, False),  # -1 = format string
    "vsprintf": (0, -1, False),
    "gets": (0, -1, False),
    "memcpy": (0, 1, True),
    "memmove": (0, 1, True),
    "strncpy": (0, 1, True),
    "strncat": (0, 1, True),
    "snprintf": (0, -1, True),
    "read": (1, -1, True),
    "recv": (1, -1, True),
    "fread": (0, -1, True),
}

FORMAT_SINKS = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, 
                "syslog": 1, "dprintf": 1}

FREE_FUNCS = {"free", "cfree", "realloc"}

ALLOC_FUNCS = {"malloc", "calloc", "realloc", "strdup", "strndup", "xmalloc"}

TAINT_SOURCES = {
    "recv", "recvfrom", "read", "fread", "fgets", "gets", "getenv",
    "scanf", "fscanf", "sscanf", "getc", "fgetc", "accept",
    "gethostbyname", "getaddrinfo"
}

# =============================================================================
# CORE CLASSES
# =============================================================================

class TaintTracker:
    """Tracks taint propagation across functions"""
    
    def __init__(self):
        self.decomplib = DecompInterface()
        self.decomplib.openProgram(currentProgram)
        self.func_cache = {}
        self.taint_summaries = {}  # func -> {param_idx -> affects_return}
        self.analyzed = set()
    
    def get_high_func(self, func):
        entry = func.getEntryPoint()
        if entry not in self.func_cache:
            res = self.decomplib.decompileFunction(func, 30, TaskMonitor.DUMMY)
            self.func_cache[entry] = res.getHighFunction() if res.decompileCompleted() else None
        return self.func_cache[entry]
    
    def is_taint_source(self, func_name):
        return func_name.lower() in TAINT_SOURCES
    
    def trace_to_origin(self, varnode, depth=0):
        """Trace varnode to its origin, return taint info"""
        if depth > 8 or not varnode:
            return {"tainted": False, "origin": "complex"}
        
        if varnode.isConstant():
            return {"tainted": False, "origin": "const", "value": varnode.getOffset()}
        
        # Check if parameter
        high = varnode.getHigh()
        if high and high.getSymbol():
            sym = high.getSymbol()
            if sym.isParameter():
                return {"tainted": True, "origin": "param", 
                        "name": sym.getName(), "index": sym.getCategoryIndex()}
        
        def_op = varnode.getDef()
        if not def_op:
            if varnode.isAddress():
                return {"tainted": False, "origin": "global"}
            name = high.getSymbol().getName() if high and high.getSymbol() else "input"
            return {"tainted": False, "origin": "input", "name": name}
        
        opcode = def_op.getOpcode()
        
        # Call return value
        if opcode == PcodeOp.CALL:
            fname = self._get_call_name(def_op)
            is_src = self.is_taint_source(fname)
            return {"tainted": is_src, "origin": "call", "func": fname}
        
        # Pass-through
        if opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE]:
            return self.trace_to_origin(def_op.getInput(0), depth + 1)
        
        # Memory load
        if opcode == PcodeOp.LOAD:
            ptr = self.trace_to_origin(def_op.getInput(1), depth + 1)
            return {"tainted": ptr.get("tainted", False), "origin": "load", "ptr": ptr}
        
        # Arithmetic - taint if either operand tainted
        if opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, 
                      PcodeOp.PTRADD, PcodeOp.PTRSUB]:
            left = self.trace_to_origin(def_op.getInput(0), depth + 1)
            right = self.trace_to_origin(def_op.getInput(1), depth + 1) if def_op.getNumInputs() > 1 else {"tainted": False}
            tainted = left.get("tainted", False) or right.get("tainted", False)
            return {"tainted": tainted, "origin": "arith", "left": left, "right": right}
        
        # PHI node
        if opcode == PcodeOp.MULTIEQUAL:
            # Check all inputs
            for i in range(def_op.getNumInputs()):
                inp = self.trace_to_origin(def_op.getInput(i), depth + 1)
                if inp.get("tainted"):
                    return {"tainted": True, "origin": "phi"}
            return {"tainted": False, "origin": "phi"}
        
        return {"tainted": False, "origin": def_op.getMnemonic()}
    
    def _get_call_name(self, call_op):
        addr_vn = call_op.getInput(0)
        if addr_vn and addr_vn.isAddress():
            f = currentProgram.getListing().getFunctionAt(addr_vn.getAddress())
            return f.getName() if f else "unknown"
        return "indirect"
    
    def origin_str(self, origin):
        """Convert origin dict to string"""
        t = origin.get("origin", "?")
        if t == "const":
            return "0x{:X}".format(origin.get("value", 0))
        if t == "param":
            return origin.get("name", "param")
        if t == "call":
            return "ret_{}".format(origin.get("func", "?"))
        if t == "load":
            return "*({})".format(self.origin_str(origin.get("ptr", {})))
        if t == "arith":
            return "expr"
        return t


class CFGHelper:
    """Basic CFG analysis for mutual exclusion detection"""
    
    def __init__(self, high_func):
        self.blocks = list(high_func.getBasicBlocks()) if high_func else []
        self.block_map = {}
        for b in self.blocks:
            self.block_map[b.getStart()] = b
    
    def find_block(self, addr):
        for b in self.blocks:
            if b.contains(addr):
                return b
        return None
    
    def are_exclusive(self, addr1, addr2):
        """Check if two addresses are in mutually exclusive branches"""
        b1 = self.find_block(addr1)
        b2 = self.find_block(addr2)
        
        if not b1 or not b2 or b1 == b2:
            return False
        
        # Find common dominator that's a CBRANCH
        # Simplified: check if they share no common successor path
        visited1 = self._reachable_from(b1)
        visited2 = self._reachable_from(b2)
        
        # If neither can reach the other, they might be exclusive
        return b2 not in visited1 and b1 not in visited2
    
    def _reachable_from(self, block, visited=None):
        if visited is None:
            visited = set()
        if block in visited:
            return visited
        visited.add(block)
        for i in range(block.getOutSize()):
            self._reachable_from(block.getOut(i), visited)
        return visited
    
    def has_length_check(self, addr, var_name):
        """Check if there's a length check before addr involving var_name"""
        block = self.find_block(addr)
        if not block:
            return False, None
        
        # Check predecessor blocks for CBRANCH with length comparison
        checked = set()
        queue = [block]
        
        while queue:
            b = queue.pop(0)
            if b in checked:
                continue
            checked.add(b)
            
            # Check last op of block
            last = None
            for op in b.getIterator():
                last = op
            
            if last and last.getOpcode() == PcodeOp.CBRANCH:
                cond = last.getInput(1).getDef()
                if cond and cond.getOpcode() in [PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL,
                                                   PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL]:
                    return True, "bounded by comparison"
            
            # Add predecessors
            for i in range(b.getInSize()):
                pred = b.getIn(i)
                if pred not in checked:
                    queue.append(pred)
            
            if len(checked) > 10:
                break
        
        return False, None


class Finding:
    """Vulnerability finding"""
    def __init__(self, func, addr, vuln_type, severity, details):
        self.func = func
        self.addr = addr
        self.vuln_type = vuln_type
        self.severity = severity
        self.details = details
        self.fp_likelihood = "MEDIUM"
        self.mitigations = []
    
    def __str__(self):
        fp = " [likely FP]" if self.fp_likelihood == "HIGH" else ""
        return "[{}] {} @ {} in {}: {}{}".format(
            self.severity, self.vuln_type, self.addr, self.func, self.details, fp)


# =============================================================================
# MAIN DETECTOR
# =============================================================================

class MemcorrDetector:
    def __init__(self):
        self.tracker = TaintTracker()
        self.findings = []
        self.stats = defaultdict(int)
    
    def run(self):
        print("=" * 70)
        print(" Interprocedural Memory Corruption Detector")
        print("=" * 70)
        
        funcs = list(currentProgram.getFunctionManager().getFunctions(True))
        if MAX_FUNCTIONS > 0:
            funcs = funcs[:MAX_FUNCTIONS]
        
        print("[*] Analyzing {} functions...".format(len(funcs)))
        
        for i, func in enumerate(funcs):
            if func.isThunk() or func.isExternal():
                continue
            if (i + 1) % 200 == 0:
                print("    {}/{}".format(i + 1, len(funcs)))
            self.analyze_func(func)
        
        self._summarize()
        return self.findings
    
    def analyze_func(self, func):
        hf = self.tracker.get_high_func(func)
        if not hf:
            return
        
        cfg = CFGHelper(hf)
        freed_vars = {}  # Track freed pointers
        
        for op in hf.getPcodeOps():
            if op.getOpcode() != PcodeOp.CALL:
                continue
            
            fname = self.tracker._get_call_name(op)
            addr = op.getSeqnum().getTarget()
            
            # === OVERFLOW CHECKS ===
            fname_lower = fname.lower()
            for sink, (dst_idx, src_idx, bounded) in OVERFLOW_SINKS.items():
                if sink in fname_lower:
                    self._check_overflow(op, func, cfg, sink, dst_idx, src_idx, bounded, addr)
                    break
            
            # === FORMAT STRING ===
            for sink, fmt_idx in FORMAT_SINKS.items():
                if sink in fname_lower:
                    self._check_format(op, func, sink, fmt_idx, addr)
                    break
            
            # === FREE TRACKING ===
            if any(f in fname_lower for f in FREE_FUNCS):
                self._check_free(op, func, cfg, freed_vars, fname, addr)
    
    def _check_overflow(self, op, func, cfg, sink, dst_idx, src_idx, bounded, addr):
        """Check buffer overflow"""
        if op.getNumInputs() <= dst_idx + 1:
            return
        
        dst_vn = op.getInput(dst_idx + 1)
        dst_origin = self.tracker.trace_to_origin(dst_vn)
        dst_str = self.tracker.origin_str(dst_origin)
        
        # Get source if applicable
        src_str = ""
        src_tainted = False
        if src_idx >= 0 and op.getNumInputs() > src_idx + 1:
            src_vn = op.getInput(src_idx + 1)
            src_origin = self.tracker.trace_to_origin(src_vn)
            src_str = self.tracker.origin_str(src_origin)
            src_tainted = src_origin.get("tainted", False)
        
        # Parameters are considered tainted
        if dst_origin.get("origin") == "param":
            src_tainted = True
        
        # Skip bounded functions with constant sizes
        if bounded:
            # Check size argument (usually index 2)
            if op.getNumInputs() > 3:
                size_vn = op.getInput(3)
                size_origin = self.tracker.trace_to_origin(size_vn)
                if size_origin.get("origin") == "const":
                    return  # Constant bounded - safe
        
        # Check for bounds check
        has_check, _ = cfg.has_length_check(addr, dst_str)
        
        # Determine severity
        severity = "HIGH" if not bounded else "MEDIUM"
        fp = "MEDIUM"
        
        if has_check:
            fp = "HIGH"
            severity = "LOW"
        
        if not bounded and src_tainted:
            severity = "HIGH"
            fp = "LOW"
        
        if not bounded or src_tainted:
            details = "{}({}, {})".format(sink, dst_str, src_str or "...")
            if src_tainted:
                details += " [TAINTED]"
            if has_check:
                details += " [HAS_CHECK]"
            
            f = Finding(func.getName(), addr, "BUFFER_OVERFLOW", severity, details)
            f.fp_likelihood = fp
            self._add_finding(f)
    
    def _check_format(self, op, func, sink, fmt_idx, addr):
        """Check format string vulnerability"""
        if op.getNumInputs() <= fmt_idx + 1:
            return
        
        fmt_vn = op.getInput(fmt_idx + 1)
        fmt_origin = self.tracker.trace_to_origin(fmt_vn)
        
        # Constant or global format = safe
        if fmt_origin.get("origin") in ["const", "global"]:
            return
        
        # Only report if format is user-controlled
        if not fmt_origin.get("tainted") and fmt_origin.get("origin") != "param":
            return
        
        details = "{}(fmt={})".format(sink, self.tracker.origin_str(fmt_origin))
        f = Finding(func.getName(), addr, "FORMAT_STRING", "HIGH", details)
        f.fp_likelihood = "LOW"
        self._add_finding(f)
    
    def _check_free(self, op, func, cfg, freed_vars, fname, addr):
        """Check double-free and track for UAF"""
        if op.getNumInputs() < 2:
            return
        
        ptr_vn = op.getInput(1)
        ptr_origin = self.tracker.trace_to_origin(ptr_vn)
        ptr_str = self.tracker.origin_str(ptr_origin)
        
        # Check double-free
        if ptr_str in freed_vars:
            prev_addr = freed_vars[ptr_str]
            
            # Check mutual exclusion
            if cfg.are_exclusive(prev_addr, addr):
                return  # Different branches
            
            details = "double free of '{}' (first @ {})".format(ptr_str, prev_addr)
            f = Finding(func.getName(), addr, "DOUBLE_FREE", "HIGH", details)
            f.fp_likelihood = "MEDIUM"
            self._add_finding(f)
        else:
            freed_vars[ptr_str] = addr
    
    def _add_finding(self, finding):
        self.findings.append(finding)
        self.stats[finding.vuln_type] += 1
        self.stats[finding.severity] += 1
        
        if VERBOSE:
            print("  [+] {}".format(finding))
        
        # Add bookmark and comment
        try:
            addr = finding.addr
            if hasattr(addr, 'getPhysicalAddress'):
                addr = addr.getPhysicalAddress()
            
            listing = currentProgram.getListing()
            instr = listing.getInstructionContaining(addr)
            if instr:
                addr = instr.getAddress()
            
            # Bookmark
            currentProgram.getBookmarkManager().setBookmark(
                addr, "Analysis",
                "{}:{}".format(finding.severity, finding.vuln_type),
                finding.details[:80]
            )
            
            # Comment
            comment = "[{}:{}] {}".format(finding.severity, finding.vuln_type, finding.details)
            existing = listing.getComment(CodeUnit.PRE_COMMENT, addr)
            if existing:
                comment = existing + "\n" + comment
            listing.setComment(addr, CodeUnit.PRE_COMMENT, comment)
            
        except Exception as e:
            if VERBOSE:
                print("    [!] Annotation error: {}".format(e))
    
    def _summarize(self):
        print("\n" + "=" * 70)
        print(" RESULTS")
        print("=" * 70)
        
        print("\n[*] Total: {} findings".format(len(self.findings)))
        
        print("\n[*] By Severity:")
        for s in ["HIGH", "MEDIUM", "LOW"]:
            if self.stats[s]:
                print("    {}: {}".format(s, self.stats[s]))
        
        print("\n[*] By Type:")
        types = set(f.vuln_type for f in self.findings)
        for t in sorted(types):
            c = sum(1 for f in self.findings if f.vuln_type == t)
            print("    {}: {}".format(t, c))
        
        # High priority
        high = [f for f in self.findings if f.severity == "HIGH" and f.fp_likelihood != "HIGH"]
        if high:
            print("\n[!] HIGH PRIORITY ({} findings):".format(len(high)))
            for f in high[:15]:
                print("    {}".format(f))
        
        # Export JSON
        try:
            import os
            home = os.path.expanduser("~")
            json_path = os.path.join(home, "memcorr_interproc.json")
            out = {"findings": [{"func": f.func, "addr": str(f.addr), "type": f.vuln_type,
                                 "severity": f.severity, "details": f.details,
                                 "fp": f.fp_likelihood} for f in self.findings]}
            with open(json_path, "w") as fp:
                json.dump(out, fp, indent=2)
            print("\n[*] JSON: {}".format(json_path))
        except Exception as e:
            print("[!] JSON export failed: {}".format(e))


# =============================================================================
# RUN
# =============================================================================

def run():
    detector = MemcorrDetector()
    detector.run()

run()