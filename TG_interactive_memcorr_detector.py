# Memory Corruption Detector v8.0 - CALLIND Support
# @category Security
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from collections import defaultdict
import json
import os

CONFIG = {
    "max_trace_depth": 15,
}

KNOWN_EXTERNALS = {
    "getenv": {"traits": ["TAINT_RETURN"]},
    "recv": {"traits": ["TAINT_RETURN", "TAINT_PARAM"], "params": {"TAINT_PARAM": 1}},
    "read": {"traits": ["TAINT_RETURN", "TAINT_PARAM"], "params": {"TAINT_PARAM": 1}},
    "fgets": {"traits": ["TAINT_RETURN", "TAINT_PARAM"], "params": {"TAINT_PARAM": 0}},
    "fread": {"traits": ["TAINT_PARAM"], "params": {"TAINT_PARAM": 0}},
    "gets": {"traits": ["TAINT_PARAM", "COPY_UNBOUNDED"], "params": {"TAINT_PARAM": 0, "COPY_UNBOUNDED": 0}},
    
    "strcpy": {"traits": ["COPY_UNBOUNDED"], "params": {"COPY_UNBOUNDED": 0}},
    "strcat": {"traits": ["COPY_UNBOUNDED"], "params": {"COPY_UNBOUNDED": 0}},
    "sprintf": {"traits": ["COPY_UNBOUNDED", "FORMAT_SINK"], "params": {"COPY_UNBOUNDED": 0, "FORMAT_SINK": 1}},
    "vsprintf": {"traits": ["COPY_UNBOUNDED", "FORMAT_SINK"], "params": {"COPY_UNBOUNDED": 0, "FORMAT_SINK": 1}},
    
    "strncpy": {"traits": ["COPY_BOUNDED"], "params": {"COPY_BOUNDED": 0}},
    "snprintf": {"traits": ["COPY_BOUNDED", "FORMAT_SINK"], "params": {"COPY_BOUNDED": 0, "FORMAT_SINK": 2}},
    "memcpy": {"traits": ["COPY_BOUNDED"], "params": {"COPY_BOUNDED": 0}},
    
    "printf": {"traits": ["FORMAT_SINK"], "params": {"FORMAT_SINK": 0}},
    "fprintf": {"traits": ["FORMAT_SINK"], "params": {"FORMAT_SINK": 1}},
    
    "free": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},
    "malloc": {"traits": ["ALLOC_RETURN", "SIZE_FROM_PARAM"], "params": {"SIZE_FROM_PARAM": 0}},
    
    "strlen": {"traits": ["SIZE_CALC"]},
    "strcmp": {"traits": ["SAFE_IGNORE"]},
    "memset": {"traits": ["SAFE_IGNORE"]},
    "split": {"traits": ["TAINT_PARAM"], "params": {"TAINT_PARAM": 0}},
    "strtok": {"traits": ["TAINT_RETURN"]},
}


class ExternalFunctionDB:
    def __init__(self):
        self.db = dict(KNOWN_EXTERNALS)
    
    def get(self, func_name):
        if not func_name:
            return None
        normalized = func_name
        if normalized.startswith("PTR_"):
            parts = normalized[4:].split("_")
            if parts:
                normalized = parts[0]
        normalized = normalized.lstrip('_').replace('_chk', '')
        return self.db.get(func_name) or self.db.get(normalized)


class MemcorrDetectorV8:
    def __init__(self):
        self.extern_db = ExternalFunctionDB()
        self.decomplib = DecompInterface()
        self.decomplib.openProgram(currentProgram)
        self.findings = []
        self.thunk_map = {}
        self.got_map = {}
        self._build_call_maps()
    
    def _build_call_maps(self):
        print("[*] Building call resolution maps...")
        
        for func in currentProgram.getFunctionManager().getFunctions(True):
            if func.isThunk():
                thunked = func.getThunkedFunction(False)
                if thunked:
                    self.thunk_map[func.getEntryPoint()] = thunked.getName()
                    self.thunk_map[func.getName()] = thunked.getName()
        
        for sym in currentProgram.getSymbolTable().getAllSymbols(True):
            name = sym.getName()
            if name.startswith("PTR_"):
                parts = name[4:].rsplit("_", 1)
                if parts:
                    target = parts[0]
                    self.got_map[sym.getAddress()] = target
                    self.got_map[name] = target
        
        print("    Thunks: {}, GOT ptrs: {}".format(len(self.thunk_map), len(self.got_map)))
    
    def resolve_call_target(self, call_op):
        """Resolve CALL or CALLIND target"""
        if call_op.getNumInputs() < 1:
            return None
        
        addr_vn = call_op.getInput(0)
        if not addr_vn:
            return None
        
        # Direct address
        if addr_vn.isAddress():
            addr = addr_vn.getAddress()
            if addr in self.thunk_map:
                return self.thunk_map[addr]
            func = currentProgram.getListing().getFunctionAt(addr)
            if func:
                name = func.getName()
                if name in self.thunk_map:
                    return self.thunk_map[name]
                return name
        
        # Constant address
        if addr_vn.isConstant():
            addr_val = addr_vn.getOffset()
            addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
            if addr in self.thunk_map:
                return self.thunk_map[addr]
            func = currentProgram.getListing().getFunctionAt(addr)
            if func:
                return func.getName()
        
        # Indirect - trace through LOAD from GOT
        return self._resolve_indirect(addr_vn, 0)
    
    def _resolve_indirect(self, vn, depth):
        if depth > 5 or not vn:
            return None
        
        # Check symbol name for PTR_ prefix
        high = vn.getHigh()
        if high and high.getSymbol():
            name = high.getSymbol().getName()
            if name in self.got_map:
                return self.got_map[name]
            if name.startswith("PTR_"):
                parts = name[4:].rsplit("_", 1)
                if parts:
                    return parts[0]
        
        def_op = vn.getDef()
        if not def_op:
            return None
        
        opcode = def_op.getOpcode()
        
        if opcode == PcodeOp.LOAD:
            # Check what address we're loading from
            ptr_vn = def_op.getInput(1)
            if ptr_vn:
                # Check symbol at load address
                ptr_high = ptr_vn.getHigh()
                if ptr_high and ptr_high.getSymbol():
                    sym_name = ptr_high.getSymbol().getName()
                    if sym_name in self.got_map:
                        return self.got_map[sym_name]
                    if sym_name.startswith("PTR_"):
                        parts = sym_name[4:].rsplit("_", 1)
                        if parts:
                            return parts[0]
                
                # Try to get address
                if ptr_vn.isAddress():
                    addr = ptr_vn.getAddress()
                    if addr in self.got_map:
                        return self.got_map[addr]
                    # Check symbol at address
                    sym = currentProgram.getSymbolTable().getPrimarySymbol(addr)
                    if sym:
                        name = sym.getName()
                        if name in self.got_map:
                            return self.got_map[name]
                        if name.startswith("PTR_"):
                            return name[4:].rsplit("_", 1)[0]
                
                return self._resolve_indirect(ptr_vn, depth + 1)
        
        if opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.PTRSUB, PcodeOp.PTRADD]:
            return self._resolve_indirect(def_op.getInput(0), depth + 1)
        
        return None
    
    def is_local_var(self, varnode, hf):
        if not varnode:
            return False, None, None
        
        high = varnode.getHigh()
        if high:
            sym = high.getSymbol()
            if sym:
                name = sym.getName()
                # Check for stack storage
                if hasattr(sym, 'getStorage'):
                    storage = sym.getStorage()
                    if storage and storage.isStackStorage():
                        dt = high.getDataType()
                        size = dt.getLength() if dt else None
                        return True, name, size
                # Local non-param
                if not sym.isGlobal() and not sym.isParameter():
                    dt = high.getDataType()
                    size = dt.getLength() if dt else None
                    return True, name, size
        
        # Check definition
        def_op = varnode.getDef()
        if def_op and def_op.getOpcode() == PcodeOp.PTRSUB:
            high = varnode.getHigh()
            if high:
                dt = high.getDataType()
                size = dt.getLength() if dt else None
                sym = high.getSymbol()
                name = sym.getName() if sym else "local"
                return True, name, size
            return True, "stack_var", None
        
        return False, None, None
    
    def trace_taint(self, varnode, depth=0):
        if depth > CONFIG["max_trace_depth"] or not varnode:
            return False, "?"
        
        if varnode.isConstant():
            return False, "const"
        
        high = varnode.getHigh()
        if high and high.getSymbol():
            sym = high.getSymbol()
            name = sym.getName()
            if sym.isParameter():
                return True, "param:{}".format(name)
            if sym.isGlobal():
                if any(x in name.lower() for x in ['cookie', 'query', 'input', 'user', 'http', 'request', 'env', 'arg', 'data', 'buf', 'str', 'split']):
                    return True, "global:{}".format(name)
        
        def_op = varnode.getDef()
        if not def_op:
            return False, "input"
        
        opcode = def_op.getOpcode()
        
        # Handle both CALL and CALLIND
        if opcode in [PcodeOp.CALL, PcodeOp.CALLIND]:
            func_name = self.resolve_call_target(def_op)
            if func_name:
                classification = self.extern_db.get(func_name)
                if classification and "TAINT_RETURN" in classification.get("traits", []):
                    return True, "ret:{}".format(func_name)
            return False, "ret:{}".format(func_name or "?")
        
        if opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE]:
            return self.trace_taint(def_op.getInput(0), depth + 1)
        
        if opcode == PcodeOp.LOAD:
            ptr_taint, ptr_src = self.trace_taint(def_op.getInput(1), depth + 1)
            if ptr_taint:
                return True, "*({})".format(ptr_src)
            return False, "load"
        
        if opcode == PcodeOp.PTRADD:
            base_taint, base_src = self.trace_taint(def_op.getInput(0), depth + 1)
            if base_taint:
                return True, "{}[i]".format(base_src)
            return False, "array"
        
        if opcode == PcodeOp.PTRSUB:
            return self.trace_taint(def_op.getInput(0), depth + 1)
        
        if opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, PcodeOp.INT_OR, PcodeOp.INT_AND]:
            for i in range(def_op.getNumInputs()):
                t, s = self.trace_taint(def_op.getInput(i), depth + 1)
                if t:
                    return True, s
            return False, "arith"
        
        if opcode == PcodeOp.MULTIEQUAL:
            for i in range(def_op.getNumInputs()):
                t, s = self.trace_taint(def_op.getInput(i), depth + 1)
                if t:
                    return True, s
            return False, "phi"
        
        return False, "other"
    
    def run(self):
        print("=" * 70)
        print(" Memory Corruption Detector v8.0 - CALLIND Support")
        print("=" * 70)
        
        funcs = list(currentProgram.getFunctionManager().getFunctions(True))
        print("[*] Analyzing {} functions...".format(len(funcs)))
        
        call_count = 0
        resolved_count = 0
        
        for i, func in enumerate(funcs):
            if func.isThunk() or func.isExternal():
                continue
            if (i + 1) % 200 == 0:
                print("    {}/{} ({} calls, {} resolved)".format(
                    i + 1, len(funcs), call_count, resolved_count))
            
            res = self.decomplib.decompileFunction(func, 60, TaskMonitor.DUMMY)
            if not res.decompileCompleted():
                continue
            
            hf = res.getHighFunction()
            if not hf:
                continue
            
            freed_ptrs = {}
            
            # Iterate using hasNext/next pattern
            ops_iter = hf.getPcodeOps()
            while ops_iter.hasNext():
                op = ops_iter.next()
                opcode = op.getOpcode()
                
                # Check both CALL and CALLIND
                if opcode not in [PcodeOp.CALL, PcodeOp.CALLIND]:
                    continue
                
                call_count += 1
                addr = op.getSeqnum().getTarget()
                call_name = self.resolve_call_target(op)
                
                if call_name:
                    resolved_count += 1
                else:
                    continue
                
                classification = self.extern_db.get(call_name)
                if not classification:
                    continue
                
                traits = classification.get("traits", [])
                params = classification.get("params", {})
                
                if "COPY_UNBOUNDED" in traits:
                    self._check_unbounded(op, func, hf, call_name, params.get("COPY_UNBOUNDED", 0), addr)
                
                if "FORMAT_SINK" in traits:
                    self._check_format(op, func, hf, call_name, params.get("FORMAT_SINK", 0), addr)
                
                if "FREE_PTR" in traits:
                    self._check_free(op, func, freed_ptrs, params.get("FREE_PTR", 0), addr)
        
        print("\n[*] Call resolution: {}/{} resolved".format(resolved_count, call_count))
        self._summarize()
        return self.findings
    
    def _check_unbounded(self, op, func, hf, call_name, dst_idx, addr):
        if op.getNumInputs() <= dst_idx + 1:
            return
        
        dst_vn = op.getInput(dst_idx + 1)
        is_local, local_name, local_size = self.is_local_var(dst_vn, hf)
        
        src_tainted = False
        src_desc = ""
        
        if call_name in ["sprintf", "vsprintf"]:
            for i in range(3, op.getNumInputs()):
                t, s = self.trace_taint(op.getInput(i))
                if t:
                    src_tainted = True
                    src_desc = s
                    break
        else:
            if op.getNumInputs() > dst_idx + 2:
                src_tainted, src_desc = self.trace_taint(op.getInput(dst_idx + 2))
        
        if is_local:
            severity = "HIGH" if src_tainted else "MEDIUM"
            size_str = "[{}]".format(local_size) if local_size else ""
            details = "{}(dst={}{}) - unbounded write to local buffer".format(
                call_name, local_name or "local", size_str)
            if src_tainted:
                details += " [TAINTED: {}]".format(src_desc)
            self._add_finding(func.getName(), addr, "STACK_BUFFER_OVERFLOW", severity, details)
        elif src_tainted:
            details = "{}() with tainted source [{}]".format(call_name, src_desc)
            self._add_finding(func.getName(), addr, "BUFFER_OVERFLOW", "HIGH", details)
    
    def _check_format(self, op, func, hf, call_name, fmt_idx, addr):
        if op.getNumInputs() <= fmt_idx + 1:
            return
        
        fmt_vn = op.getInput(fmt_idx + 1)
        if fmt_vn.isConstant():
            return
        
        fmt_tainted, fmt_src = self.trace_taint(fmt_vn)
        if fmt_tainted:
            details = "{}(fmt={}) - user-controlled format".format(call_name, fmt_src)
            self._add_finding(func.getName(), addr, "FORMAT_STRING", "HIGH", details)
    
    def _check_free(self, op, func, freed_ptrs, ptr_idx, addr):
        if op.getNumInputs() <= ptr_idx + 1:
            return
        
        ptr_vn = op.getInput(ptr_idx + 1)
        _, ptr_desc = self.trace_taint(ptr_vn)
        
        if ptr_desc in freed_ptrs:
            details = "double free of '{}' (first @ {})".format(ptr_desc, freed_ptrs[ptr_desc])
            self._add_finding(func.getName(), addr, "DOUBLE_FREE", "HIGH", details)
        else:
            freed_ptrs[ptr_desc] = addr
    
    def _add_finding(self, func_name, addr, vuln_type, severity, details):
        key = (func_name, str(addr), vuln_type)
        for f in self.findings:
            if (f["func"], f["addr"], f["type"]) == key:
                return
        
        self.findings.append({
            "func": func_name,
            "addr": str(addr),
            "type": vuln_type,
            "severity": severity,
            "details": details
        })
        
        try:
            paddr = addr
            if hasattr(paddr, 'getPhysicalAddress'):
                paddr = paddr.getPhysicalAddress()
            currentProgram.getBookmarkManager().setBookmark(
                paddr, "Analysis", "{}:{}".format(severity, vuln_type),
                details[:80])
        except:
            pass
    
    def _summarize(self):
        print("\n" + "=" * 70)
        print(" RESULTS")
        print("=" * 70)
        
        print("\n[*] Total: {} findings".format(len(self.findings)))
        
        if self.findings:
            print("\n[*] By Severity:")
            for sev in ["HIGH", "MEDIUM", "LOW"]:
                count = sum(1 for f in self.findings if f["severity"] == sev)
                if count:
                    print("    {}: {}".format(sev, count))
            
            print("\n[!] Findings:")
            for f in sorted(self.findings, key=lambda x: (x["severity"] != "HIGH", x["func"])):
                print("    [{}/{}] {} @ {}".format(f["severity"], f["type"], f["func"], f["addr"]))
                print("        {}".format(f["details"][:80]))
        
        try:
            out_path = os.path.join(os.path.expanduser("~"), "memcorr_v8.json")
            with open(out_path, "w") as fp:
                json.dump({"findings": self.findings}, fp, indent=2)
            print("\n[*] Results: {}".format(out_path))
        except:
            pass


def run():
    detector = MemcorrDetectorV8()
    detector.run()

run()
