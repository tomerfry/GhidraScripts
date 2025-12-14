# Memory Corruption Detector v2.0 - False Positive Mitigated
# Based on analysis of wget-1.19.1 findings
# @category Security
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import CodeUnit
from collections import defaultdict
import json
import os
import re

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG = {
    "max_functions": 0,
    "max_trace_depth": 8,
    "verbose": False,
    "add_comments": True,
    "add_bookmarks": True,
}

# =============================================================================
# FIX #1: Exact function name matching (not substring)
# =============================================================================

# Map of EXACT dangerous function names
OVERFLOW_SINKS = {
    # Unbounded - HIGH risk
    "strcpy":   {"dst": 0, "src": 1, "bounded": False, "severity": "HIGH"},
    "strcat":   {"dst": 0, "src": 1, "bounded": False, "severity": "HIGH"},
    "sprintf":  {"dst": 0, "fmt": 1, "bounded": False, "severity": "HIGH"},
    "vsprintf": {"dst": 0, "fmt": 1, "bounded": False, "severity": "HIGH"},
    "gets":     {"dst": 0, "bounded": False, "severity": "CRITICAL"},
    
    # Bounded - MEDIUM risk (only if size is user-controlled)
    "strncpy":  {"dst": 0, "src": 1, "size": 2, "bounded": True, "severity": "MEDIUM"},
    "strncat":  {"dst": 0, "src": 1, "size": 2, "bounded": True, "severity": "MEDIUM"},
    "snprintf": {"dst": 0, "size": 1, "fmt": 2, "bounded": True, "severity": "LOW"},
    "memcpy":   {"dst": 0, "src": 1, "size": 2, "bounded": True, "severity": "MEDIUM"},
    "memmove":  {"dst": 0, "src": 1, "size": 2, "bounded": True, "severity": "MEDIUM"},
    "read":     {"dst": 1, "size": 2, "bounded": True, "severity": "MEDIUM"},
    "recv":     {"dst": 1, "size": 2, "bounded": True, "severity": "MEDIUM"},
}

# FIX #6: Correct format string argument positions
FORMAT_STRING_SINKS = {
    "printf":   {"fmt": 0},  # printf(fmt, ...)
    "fprintf":  {"fmt": 1},  # fprintf(FILE*, fmt, ...)
    "dprintf":  {"fmt": 1},  # dprintf(fd, fmt, ...)
    "sprintf":  {"fmt": 1},  # sprintf(buf, fmt, ...)
    "snprintf": {"fmt": 2},  # snprintf(buf, size, fmt, ...)
    "syslog":   {"fmt": 1},  # syslog(priority, fmt, ...)
}

TAINT_SOURCES = {
    "recv", "recvfrom", "read", "fread", "fgets", "getenv",
    "scanf", "fscanf", "sscanf", "getc", "fgetc", "accept",
    "gethostbyname", "getaddrinfo"
}

# Functions that should NOT trigger "gets" detection
GETS_FALSE_POSITIVES = {
    "getsockname", "getsockopt", "getservbyname", "getservbyport",
    "gethostbyname", "gethostbyaddr", "getaddrinfo", "getnameinfo",
    "getpeername", "getenv", "getcwd", "getline", "getdelim"
}

# =============================================================================
# IMPROVED TAINT TRACKER
# =============================================================================

class ImprovedTaintTracker:
    def __init__(self):
        self.decomplib = DecompInterface()
        self.decomplib.openProgram(currentProgram)
        self.func_cache = {}
        # FIX #5: Track strlen-malloc correlations
        self.strlen_vars = {}  # varnode -> source_varnode
        self.malloc_sizes = {} # varnode -> size_origin
    
    def get_high_func(self, func):
        entry = func.getEntryPoint()
        if entry not in self.func_cache:
            res = self.decomplib.decompileFunction(func, 30, TaskMonitor.DUMMY)
            self.func_cache[entry] = res.getHighFunction() if res.decompileCompleted() else None
        return self.func_cache[entry]
    
    def get_exact_func_name(self, call_op):
        """Get EXACT function name, not substring"""
        addr_vn = call_op.getInput(0)
        if addr_vn and addr_vn.isAddress():
            f = currentProgram.getListing().getFunctionAt(addr_vn.getAddress())
            if f:
                name = f.getName()
                # Strip common prefixes/suffixes
                for prefix in ["__", "_"]:
                    if name.startswith(prefix):
                        name = name[len(prefix):]
                for suffix in ["_r", "_s", "_l"]:
                    if name.endswith(suffix):
                        name = name[:-len(suffix)]
                return name
        return None
    
    def is_global_constant(self, varnode):
        """FIX #7: Check if varnode is a global constant"""
        if not varnode:
            return False
        
        # Direct address reference (e.g., &DAT_00153xxx)
        if varnode.isAddress():
            addr = varnode.getAddress()
            mem = currentProgram.getMemory()
            block = mem.getBlock(addr)
            if block:
                # Check if in read-only section
                name = block.getName().lower()
                if any(x in name for x in [".rodata", ".rdata", ".text", "const"]):
                    return True
                # Check write permission
                if not block.isWrite():
                    return True
        
        # Trace back through COPY/CAST
        def_op = varnode.getDef()
        if def_op:
            opcode = def_op.getOpcode()
            if opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT]:
                return self.is_global_constant(def_op.getInput(0))
            # PTRSUB from address space
            if opcode == PcodeOp.PTRSUB:
                base = def_op.getInput(0)
                if base.isConstant() or base.isAddress():
                    return True
        
        return varnode.isConstant()
    
    def trace_origin(self, varnode, depth=0):
        """Trace origin with improved struct field handling"""
        if depth > CONFIG["max_trace_depth"] or not varnode:
            return {"type": "COMPLEX", "expr": "...", "tainted": False}
        
        if varnode.isConstant():
            return {"type": "CONST", "value": varnode.getOffset(), "tainted": False}
        
        # Check global constant
        if self.is_global_constant(varnode):
            return {"type": "GLOBAL_CONST", "tainted": False}
        
        # Check parameter
        high = varnode.getHigh()
        if high and high.getSymbol():
            sym = high.getSymbol()
            if sym.isParameter():
                return {"type": "PARAM", "name": sym.getName(), 
                        "index": sym.getCategoryIndex(), "tainted": True}
        
        def_op = varnode.getDef()
        if not def_op:
            name = high.getSymbol().getName() if high and high.getSymbol() else "input"
            return {"type": "INPUT", "name": name, "tainted": False}
        
        opcode = def_op.getOpcode()
        
        # Function call
        if opcode == PcodeOp.CALL:
            fname = self.get_exact_func_name(def_op)
            is_taint = fname and fname.lower() in TAINT_SOURCES
            
            # FIX #5: Track strlen results
            if fname and "strlen" in fname.lower():
                if def_op.getNumInputs() > 1:
                    arg = def_op.getInput(1)
                    return {"type": "STRLEN", "of": self.trace_origin(arg, depth+1), 
                            "tainted": False, "strlen_src": arg}
            
            # Track malloc/xmalloc results
            if fname and any(x in fname.lower() for x in ["malloc", "alloc", "xmalloc"]):
                size_origin = None
                if def_op.getNumInputs() > 1:
                    size_origin = self.trace_origin(def_op.getInput(1), depth+1)
                return {"type": "ALLOC", "func": fname, "size": size_origin, "tainted": False}
            
            return {"type": "CALL", "func": fname or "unknown", "tainted": is_taint}
        
        # Pass-through
        if opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE]:
            return self.trace_origin(def_op.getInput(0), depth + 1)
        
        # Memory load - FIX #4: Include offset in tracking
        if opcode == PcodeOp.LOAD:
            ptr_origin = self.trace_origin(def_op.getInput(1), depth + 1)
            return {"type": "LOAD", "ptr": ptr_origin, 
                    "tainted": ptr_origin.get("tainted", False)}
        
        # FIX #4: Struct field access - track offset separately
        if opcode == PcodeOp.PTRSUB:
            base = self.trace_origin(def_op.getInput(0), depth + 1)
            offset_vn = def_op.getInput(1)
            offset = offset_vn.getOffset() if offset_vn.isConstant() else "var"
            return {"type": "FIELD", "base": base, "offset": offset,
                    "field_key": "{}+0x{:x}".format(
                        self._base_name(base), offset if isinstance(offset, int) else 0),
                    "tainted": base.get("tainted", False)}
        
        if opcode == PcodeOp.PTRADD:
            base = self.trace_origin(def_op.getInput(0), depth + 1)
            index = self.trace_origin(def_op.getInput(1), depth + 1)
            return {"type": "INDEX", "base": base, "index": index,
                    "tainted": base.get("tainted") or index.get("tainted", False)}
        
        # Arithmetic - check for strlen correlation
        if opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT]:
            left = self.trace_origin(def_op.getInput(0), depth + 1)
            right = self.trace_origin(def_op.getInput(1), depth + 1) if def_op.getNumInputs() > 1 else {"tainted": False}
            
            # FIX #5: Check if this is strlen + constant (allocation pattern)
            has_strlen = left.get("type") == "STRLEN" or right.get("type") == "STRLEN"
            strlen_src = left.get("strlen_src") or right.get("strlen_src")
            
            return {"type": "ARITH", "op": def_op.getMnemonic(), 
                    "left": left, "right": right,
                    "has_strlen": has_strlen, "strlen_src": strlen_src,
                    "tainted": left.get("tainted") or right.get("tainted", False)}
        
        # PHI node
        if opcode == PcodeOp.MULTIEQUAL:
            name = high.getSymbol().getName() if high and high.getSymbol() else "phi"
            return {"type": "PHI", "name": name, "tainted": False}
        
        return {"type": "OTHER", "op": def_op.getMnemonic(), "tainted": False}
    
    def _base_name(self, origin):
        """Get base name from origin for field tracking"""
        t = origin.get("type", "?")
        if t == "PARAM":
            return origin.get("name", "param")
        if t == "CALL":
            return "ret_" + origin.get("func", "?")
        if t == "FIELD":
            return self._base_name(origin.get("base", {}))
        return "var"
    
    def origin_str(self, origin):
        """Convert origin to string"""
        if not origin:
            return "unknown"
        t = origin.get("type", "?")
        if t == "CONST":
            return "0x{:X}".format(origin.get("value", 0))
        if t == "PARAM":
            return origin.get("name", "param")
        if t == "CALL":
            return "ret_{}".format(origin.get("func", "?"))
        if t == "STRLEN":
            return "strlen({})".format(self.origin_str(origin.get("of", {})))
        if t == "ALLOC":
            return "{}(...)".format(origin.get("func", "alloc"))
        if t == "FIELD":
            return "{}.off_{:x}".format(
                self.origin_str(origin.get("base", {})),
                origin.get("offset", 0) if isinstance(origin.get("offset"), int) else 0)
        if t == "INDEX":
            return "{}[{}]".format(
                self.origin_str(origin.get("base", {})),
                self.origin_str(origin.get("index", {})))
        if t == "LOAD":
            return "*({})".format(self.origin_str(origin.get("ptr", {})))
        if t in ["GLOBAL_CONST", "INPUT", "PHI"]:
            return origin.get("name", t.lower())
        return t
    
    def check_strlen_malloc_correlation(self, dst_origin, src_origin):
        """
        FIX #5: Check if destination buffer was allocated based on strlen of source
        Pattern: buf = malloc(strlen(src) + N); strcpy(buf, src) -> SAFE
        """
        # Check if dst came from allocation
        if dst_origin.get("type") not in ["ALLOC", "INDEX"]:
            return False
        
        # Get the allocation size origin
        if dst_origin.get("type") == "ALLOC":
            size_origin = dst_origin.get("size", {})
        elif dst_origin.get("type") == "INDEX":
            base = dst_origin.get("base", {})
            if base.get("type") == "ALLOC":
                size_origin = base.get("size", {})
            else:
                return False
        else:
            return False
        
        if not size_origin:
            return False
        
        # Check if size was derived from strlen
        if not size_origin.get("has_strlen"):
            return False
        
        # Check if strlen was of the same source we're copying
        strlen_src = size_origin.get("strlen_src")
        if strlen_src:
            # This is a simplified check - in reality we'd need SSA comparison
            src_name = self.origin_str(src_origin)
            strlen_name = self.origin_str(self.trace_origin(strlen_src))
            if src_name == strlen_name or "param" in src_name.lower():
                return True
        
        return False


# =============================================================================
# IMPROVED CFG ANALYZER
# =============================================================================

class ImprovedCFGAnalyzer:
    """FIX #2: Better mutual exclusion detection including switch cases"""
    
    def __init__(self, high_func):
        self.high_func = high_func
        self.blocks = list(high_func.getBasicBlocks()) if high_func else []
        self._build_block_info()
    
    def _build_block_info(self):
        """Build block predecessor/successor info"""
        self.block_preds = defaultdict(set)
        self.block_succs = defaultdict(set)
        
        for block in self.blocks:
            for i in range(block.getOutSize()):
                succ = block.getOut(i)
                self.block_succs[block].add(succ)
                self.block_preds[succ].add(block)
    
    def find_block(self, addr):
        """Find block containing address"""
        for b in self.blocks:
            if b.contains(addr):
                return b
        return None
    
    def are_mutually_exclusive(self, addr1, addr2):
        """
        Check if two addresses are mutually exclusive.
        Handles: if/else branches, switch cases, different function paths
        """
        b1 = self.find_block(addr1)
        b2 = self.find_block(addr2)
        
        if not b1 or not b2:
            return False
        if b1 == b2:
            return False
        
        # Check if either can reach the other
        can_1_reach_2 = self._can_reach(b1, b2, set())
        can_2_reach_1 = self._can_reach(b2, b1, set())
        
        # If neither can reach the other and they share a common predecessor
        # that branches, they're likely mutually exclusive
        if not can_1_reach_2 and not can_2_reach_1:
            # Find common predecessors (potential branch points)
            common_preds = self._find_common_predecessors(b1, b2)
            for pred in common_preds:
                if self._is_branch_block(pred):
                    return True
        
        return False
    
    def _can_reach(self, start, target, visited):
        """Check if target is reachable from start"""
        if start == target:
            return True
        if start in visited:
            return False
        visited.add(start)
        
        for succ in self.block_succs.get(start, []):
            if self._can_reach(succ, target, visited):
                return True
        return False
    
    def _find_common_predecessors(self, b1, b2, max_depth=10):
        """Find blocks that can reach both b1 and b2"""
        preds1 = self._get_all_predecessors(b1, max_depth)
        preds2 = self._get_all_predecessors(b2, max_depth)
        return preds1 & preds2
    
    def _get_all_predecessors(self, block, max_depth):
        """Get all predecessor blocks up to max_depth"""
        result = set()
        queue = [(block, 0)]
        visited = set()
        
        while queue:
            b, depth = queue.pop(0)
            if b in visited or depth > max_depth:
                continue
            visited.add(b)
            
            for pred in self.block_preds.get(b, []):
                result.add(pred)
                queue.append((pred, depth + 1))
        
        return result
    
    def _is_branch_block(self, block):
        """Check if block ends with a branch (CBRANCH or BRANCHIND/switch)"""
        last_op = None
        for op in block.getIterator():
            last_op = op
        
        if last_op:
            opcode = last_op.getOpcode()
            return opcode in [PcodeOp.CBRANCH, PcodeOp.BRANCHIND]
        return False


# =============================================================================
# FINDING CLASS
# =============================================================================

class Finding:
    def __init__(self, func, addr, vuln_type, severity, details):
        self.func = func
        self.addr = addr
        self.vuln_type = vuln_type
        self.severity = severity
        self.details = details
        self.fp_reason = None
        self.is_likely_fp = False
    
    def __str__(self):
        fp = " [LIKELY_FP: {}]".format(self.fp_reason) if self.is_likely_fp else ""
        return "[{}] {} @ {}: {}{}".format(
            self.severity, self.vuln_type, self.addr, self.details, fp)


# =============================================================================
# MAIN DETECTOR
# =============================================================================

class MemcorrDetectorV2:
    def __init__(self):
        self.tracker = ImprovedTaintTracker()
        self.findings = []
        self.stats = defaultdict(int)
    
    def run(self):
        print("=" * 70)
        print(" Memory Corruption Detector v2.0 (FP-Mitigated)")
        print("=" * 70)
        
        funcs = list(currentProgram.getFunctionManager().getFunctions(True))
        if CONFIG["max_functions"] > 0:
            funcs = funcs[:CONFIG["max_functions"]]
        
        print("[*] Analyzing {} functions...".format(len(funcs)))
        
        for i, func in enumerate(funcs):
            if func.isThunk() or func.isExternal():
                continue
            if (i + 1) % 200 == 0:
                print("    {}/{}".format(i + 1, len(funcs)))
            self._analyze_function(func)
        
        self._summarize()
        return self.findings
    
    def _analyze_function(self, func):
        hf = self.tracker.get_high_func(func)
        if not hf:
            return
        
        cfg = ImprovedCFGAnalyzer(hf)
        
        # FIX #3 & #4: Track freed pointers with full context (including struct fields)
        freed_ptrs = {}  # unique_key -> (addr, origin)
        
        for op in hf.getPcodeOps():
            if op.getOpcode() != PcodeOp.CALL:
                continue
            
            fname = self.tracker.get_exact_func_name(op)
            if not fname:
                continue
            
            addr = op.getSeqnum().getTarget()
            
            # === OVERFLOW CHECKS ===
            # FIX #1: Exact match, exclude false positive patterns
            if fname in OVERFLOW_SINKS:
                # Skip if it's actually a different function
                if fname == "gets" and self._is_gets_false_positive(op):
                    continue
                self._check_overflow(op, func, cfg, fname, OVERFLOW_SINKS[fname], addr)
            
            # === FORMAT STRING ===
            if fname in FORMAT_STRING_SINKS:
                self._check_format_string(op, func, fname, FORMAT_STRING_SINKS[fname], addr)
            
            # === DOUBLE-FREE ===
            if fname == "free":
                self._check_double_free(op, func, cfg, freed_ptrs, addr)
    
    def _is_gets_false_positive(self, call_op):
        """FIX #1: Check if 'gets' is actually getsockname etc."""
        addr_vn = call_op.getInput(0)
        if addr_vn and addr_vn.isAddress():
            f = currentProgram.getListing().getFunctionAt(addr_vn.getAddress())
            if f:
                full_name = f.getName().lower()
                return any(fp in full_name for fp in GETS_FALSE_POSITIVES)
        return False
    
    def _check_overflow(self, op, func, cfg, fname, sink_info, addr):
        """Check buffer overflow with FP mitigations"""
        dst_idx = sink_info.get("dst", 0)
        if op.getNumInputs() <= dst_idx + 1:
            return
        
        dst_vn = op.getInput(dst_idx + 1)
        dst_origin = self.tracker.trace_origin(dst_vn)
        dst_str = self.tracker.origin_str(dst_origin)
        
        # Get source if applicable
        src_origin = None
        src_str = ""
        src_idx = sink_info.get("src")
        if src_idx is not None and op.getNumInputs() > src_idx + 1:
            src_vn = op.getInput(src_idx + 1)
            src_origin = self.tracker.trace_origin(src_vn)
            src_str = self.tracker.origin_str(src_origin)
        
        # Determine if tainted
        is_tainted = (dst_origin.get("tainted", False) or 
                     (src_origin and src_origin.get("tainted", False)))
        
        # FIX #5: Check strlen-malloc correlation
        if src_origin and self.tracker.check_strlen_malloc_correlation(dst_origin, src_origin):
            # Safe pattern: malloc(strlen(src)+N) then strcpy
            return
        
        # Skip bounded functions with constant sizes
        if sink_info.get("bounded", False):
            size_idx = sink_info.get("size")
            if size_idx is not None and op.getNumInputs() > size_idx + 1:
                size_vn = op.getInput(size_idx + 1)
                size_origin = self.tracker.trace_origin(size_vn)
                if size_origin.get("type") == "CONST":
                    # Constant bounded - low risk
                    if not is_tainted:
                        return
        
        # Only report if there's actual risk
        severity = sink_info["severity"]
        if not is_tainted and sink_info.get("bounded"):
            return  # Bounded with no taint = not interesting
        
        details = "{}({}, {})".format(fname, dst_str, src_str or "...")
        if is_tainted:
            details += " [TAINTED]"
        
        finding = Finding(func.getName(), addr, "BUFFER_OVERFLOW", severity, details)
        
        # Mark potential FPs
        if dst_origin.get("type") == "ALLOC" and dst_origin.get("size", {}).get("has_strlen"):
            finding.is_likely_fp = True
            finding.fp_reason = "size from strlen"
        
        self._add_finding(finding)
    
    def _check_format_string(self, op, func, fname, sink_info, addr):
        """FIX #6: Correct format string argument position"""
        fmt_idx = sink_info.get("fmt", 0)
        if op.getNumInputs() <= fmt_idx + 1:
            return
        
        fmt_vn = op.getInput(fmt_idx + 1)
        fmt_origin = self.tracker.trace_origin(fmt_vn)
        
        # FIX #7: Skip global constants
        if fmt_origin.get("type") in ["CONST", "GLOBAL_CONST"]:
            return
        
        # Only flag if format is user-controlled
        if not fmt_origin.get("tainted", False):
            return
        
        details = "{}(fmt={}) - format from user input".format(
            fname, self.tracker.origin_str(fmt_origin))
        
        finding = Finding(func.getName(), addr, "FORMAT_STRING", "HIGH", details)
        self._add_finding(finding)
    
    def _check_double_free(self, op, func, cfg, freed_ptrs, addr):
        """FIX #3 & #4: Improved double-free detection"""
        if op.getNumInputs() < 2:
            return
        
        ptr_vn = op.getInput(1)
        ptr_origin = self.tracker.trace_origin(ptr_vn)
        
        # FIX #4: Use field_key for struct fields to distinguish different fields
        if ptr_origin.get("type") == "FIELD":
            ptr_key = ptr_origin.get("field_key", self.tracker.origin_str(ptr_origin))
        elif ptr_origin.get("type") == "LOAD":
            # For loads, include more context
            ptr_key = "load_" + self.tracker.origin_str(ptr_origin)
        else:
            ptr_key = self.tracker.origin_str(ptr_origin)
        
        # Skip if it's clearly a different struct field
        if ptr_key in freed_ptrs:
            prev_addr, prev_origin = freed_ptrs[ptr_key]
            
            # FIX #2: Check mutual exclusion
            if cfg.are_mutually_exclusive(prev_addr, addr):
                # Different branches - not a real double-free
                return
            
            # FIX #3: Check if variable was reassigned between frees
            # (simplified: if it's from a different hash_table_get_pair call, skip)
            if self._likely_reassigned(ptr_origin, prev_origin):
                return
            
            details = "double free of '{}' (first @ {})".format(ptr_key, prev_addr)
            finding = Finding(func.getName(), addr, "DOUBLE_FREE", "HIGH", details)
            self._add_finding(finding)
        else:
            freed_ptrs[ptr_key] = (addr, ptr_origin)
    
    def _likely_reassigned(self, curr_origin, prev_origin):
        """FIX #3: Check if variable was likely reassigned"""
        # If origins come from different function calls, likely reassigned
        curr_call = self._find_call_in_origin(curr_origin)
        prev_call = self._find_call_in_origin(prev_origin)
        
        if curr_call and prev_call and curr_call != prev_call:
            return True
        
        return False
    
    def _find_call_in_origin(self, origin):
        """Find any function call in the origin chain"""
        if not origin:
            return None
        t = origin.get("type")
        if t == "CALL":
            return origin.get("func")
        for key in ["base", "ptr", "left", "right", "of"]:
            if key in origin:
                result = self._find_call_in_origin(origin[key])
                if result:
                    return result
        return None
    
    def _add_finding(self, finding):
        if finding.is_likely_fp:
            return  # Skip likely FPs
        
        self.findings.append(finding)
        self.stats[finding.vuln_type] += 1
        self.stats[finding.severity] += 1
        
        if CONFIG["verbose"]:
            print("  [+] {}".format(finding))
        
        try:
            paddr = finding.addr
            if hasattr(paddr, 'getPhysicalAddress'):
                paddr = paddr.getPhysicalAddress()
            
            listing = currentProgram.getListing()
            instr = listing.getInstructionContaining(paddr)
            if instr:
                paddr = instr.getAddress()
            
            if CONFIG["add_bookmarks"]:
                currentProgram.getBookmarkManager().setBookmark(
                    paddr, "Analysis",
                    "{}:{}".format(finding.severity, finding.vuln_type),
                    finding.details[:80]
                )
            
            if CONFIG["add_comments"]:
                comment = "[{}:{}] {}".format(
                    finding.severity, finding.vuln_type, finding.details)
                existing = listing.getComment(CodeUnit.PRE_COMMENT, paddr)
                if existing:
                    comment = existing + "\n" + comment
                listing.setComment(paddr, CodeUnit.PRE_COMMENT, comment)
        except:
            pass
    
    def _summarize(self):
        print("\n" + "=" * 70)
        print(" RESULTS (FP-Mitigated)")
        print("=" * 70)
        
        print("\n[*] Total: {} findings".format(len(self.findings)))
        
        # Filter out likely FPs for summary
        real_findings = [f for f in self.findings if not f.is_likely_fp]
        
        print("\n[*] By Severity:")
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sum(1 for f in real_findings if f.severity == s)
            if count:
                print("    {}: {}".format(s, count))
        
        print("\n[*] By Type:")
        for t in set(f.vuln_type for f in real_findings):
            count = sum(1 for f in real_findings if f.vuln_type == t)
            print("    {}: {}".format(t, count))
        
        # High priority
        high = [f for f in real_findings if f.severity in ["CRITICAL", "HIGH"]]
        if high:
            print("\n[!] HIGH PRIORITY ({} findings):".format(len(high)))
            for f in high[:20]:
                print("    {}".format(f))
        
        # Export JSON
        try:
            home = os.path.expanduser("~")
            json_path = os.path.join(home, "memcorr_v2.json")
            out = {"findings": [{"func": f.func, "addr": str(f.addr), 
                                "type": f.vuln_type, "severity": f.severity,
                                "details": f.details} for f in real_findings]}
            with open(json_path, "w") as fp:
                json.dump(out, fp, indent=2)
            print("\n[*] JSON: {}".format(json_path))
        except Exception as e:
            print("[!] JSON export failed: {}".format(e))


# =============================================================================
# RUN
# =============================================================================

def run():
    detector = MemcorrDetectorV2()
    detector.run()

run()