# Memory Corruption Detector v3.0 - Interactive External Classification
# Prompts user to classify unknown external functions on first encounter
# @category Security
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import CodeUnit
from collections import defaultdict
import json
import os

# =============================================================================
# EXTERNAL FUNCTION TRAITS (Multi-select categories)
# =============================================================================

TRAIT_DEFINITIONS = {
    "TAINT_RETURN": "Returns attacker-controlled/external data",
    "TAINT_PARAM": "Writes tainted data to output parameter",
    "COPY_UNBOUNDED": "Copies data without bounds (like strcpy)",
    "COPY_BOUNDED": "Copies data with size limit (like strncpy)", 
    "FORMAT_SINK": "Uses format string from parameter",
    "FREE_PTR": "Frees memory at parameter",
    "ALLOC_RETURN": "Returns allocated memory",
    "SIZE_FROM_PARAM": "Allocation size from parameter",
    "SAFE_IGNORE": "Safe/uninteresting - ignore in analysis",
}

# Parameter index prompts for traits that need them
PARAM_TRAITS = {
    "TAINT_PARAM": "Which parameter receives tainted output? (0-based)",
    "COPY_UNBOUNDED": "Destination parameter index?",
    "COPY_BOUNDED": "Destination parameter index?",
    "FORMAT_SINK": "Format string parameter index?",
    "FREE_PTR": "Freed pointer parameter index?",
    "SIZE_FROM_PARAM": "Size parameter index?",
}

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG = {
    "db_path": os.path.join(os.path.expanduser("~"), ".ghidra_extern_db.json"),
    "auto_classify_known": True,  # Pre-populate with common functions
    "prompt_on_unknown": True,    # Show dialog for unknown externals
    "max_trace_depth": 8,
}

# Pre-seeded known externals (can be extended by user)
KNOWN_EXTERNALS = {
    "recv": {"traits": ["TAINT_RETURN", "TAINT_PARAM"], "params": {"TAINT_PARAM": 1}},
    "read": {"traits": ["TAINT_RETURN", "TAINT_PARAM"], "params": {"TAINT_PARAM": 1}},
    "fread": {"traits": ["TAINT_PARAM"], "params": {"TAINT_PARAM": 0}},
    "fgets": {"traits": ["TAINT_RETURN", "TAINT_PARAM"], "params": {"TAINT_PARAM": 0}},
    "getenv": {"traits": ["TAINT_RETURN"]},
    "gets": {"traits": ["TAINT_PARAM", "COPY_UNBOUNDED"], "params": {"TAINT_PARAM": 0, "COPY_UNBOUNDED": 0}},
    "strcpy": {"traits": ["COPY_UNBOUNDED"], "params": {"COPY_UNBOUNDED": 0}},
    "strcat": {"traits": ["COPY_UNBOUNDED"], "params": {"COPY_UNBOUNDED": 0}},
    "sprintf": {"traits": ["COPY_UNBOUNDED", "FORMAT_SINK"], "params": {"COPY_UNBOUNDED": 0, "FORMAT_SINK": 1}},
    "vsprintf": {"traits": ["COPY_UNBOUNDED", "FORMAT_SINK"], "params": {"COPY_UNBOUNDED": 0, "FORMAT_SINK": 1}},
    "strncpy": {"traits": ["COPY_BOUNDED"], "params": {"COPY_BOUNDED": 0}},
    "strncat": {"traits": ["COPY_BOUNDED"], "params": {"COPY_BOUNDED": 0}},
    "snprintf": {"traits": ["COPY_BOUNDED", "FORMAT_SINK"], "params": {"COPY_BOUNDED": 0, "FORMAT_SINK": 2}},
    "memcpy": {"traits": ["COPY_BOUNDED"], "params": {"COPY_BOUNDED": 0}},
    "memmove": {"traits": ["COPY_BOUNDED"], "params": {"COPY_BOUNDED": 0}},
    "printf": {"traits": ["FORMAT_SINK"], "params": {"FORMAT_SINK": 0}},
    "fprintf": {"traits": ["FORMAT_SINK"], "params": {"FORMAT_SINK": 1}},
    "syslog": {"traits": ["FORMAT_SINK"], "params": {"FORMAT_SINK": 1}},
    "free": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},
    "malloc": {"traits": ["ALLOC_RETURN", "SIZE_FROM_PARAM"], "params": {"SIZE_FROM_PARAM": 0}},
    "calloc": {"traits": ["ALLOC_RETURN", "SIZE_FROM_PARAM"], "params": {"SIZE_FROM_PARAM": 0}},
    "realloc": {"traits": ["ALLOC_RETURN", "FREE_PTR", "SIZE_FROM_PARAM"], "params": {"FREE_PTR": 0, "SIZE_FROM_PARAM": 1}},
    "xmalloc": {"traits": ["ALLOC_RETURN", "SIZE_FROM_PARAM"], "params": {"SIZE_FROM_PARAM": 0}},
    "strdup": {"traits": ["ALLOC_RETURN", "TAINT_RETURN"]},
    "strlen": {"traits": ["SAFE_IGNORE"]},
    "strcmp": {"traits": ["SAFE_IGNORE"]},
    "memcmp": {"traits": ["SAFE_IGNORE"]},
    "getsockname": {"traits": ["SAFE_IGNORE"]},
    "getsockopt": {"traits": ["SAFE_IGNORE"]},
}

# =============================================================================
# EXTERNAL FUNCTION DATABASE
# =============================================================================

class ExternalFunctionDB:
    """Persistent database of external function classifications"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.db = {}
        self.load()
        
        # Merge known externals
        if CONFIG["auto_classify_known"]:
            for name, info in KNOWN_EXTERNALS.items():
                if name not in self.db:
                    self.db[name] = info
    
    def load(self):
        """Load database from disk"""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    self.db = json.load(f)
            except:
                self.db = {}
    
    def save(self):
        """Save database to disk"""
        try:
            with open(self.db_path, 'w') as f:
                json.dump(self.db, f, indent=2)
        except Exception as e:
            print("[!] Failed to save external DB: {}".format(e))
    
    def get(self, func_name):
        """Get classification for function, or None if unknown"""
        # Normalize name (strip leading underscores)
        normalized = func_name.lstrip('_')
        return self.db.get(normalized) or self.db.get(func_name)
    
    def set(self, func_name, traits, params=None):
        """Store classification for function"""
        normalized = func_name.lstrip('_')
        self.db[normalized] = {
            "traits": traits,
            "params": params or {}
        }
        self.save()
    
    def has(self, func_name):
        """Check if function is classified"""
        normalized = func_name.lstrip('_')
        return normalized in self.db or func_name in self.db


# =============================================================================
# INTERACTIVE DIALOG
# =============================================================================

class ExternalClassifier:
    """Handles interactive classification of unknown externals"""
    
    def __init__(self, db):
        self.db = db
        self.session_skipped = set()  # Skip for this session only
    
    def classify_external(self, func_name, call_context=None):
        """
        Prompt user to classify an external function.
        Returns classification dict or None if skipped.
        """
        if func_name in self.session_skipped:
            return None
        
        # Check if already classified
        existing = self.db.get(func_name)
        if existing:
            return existing
        
        if not CONFIG["prompt_on_unknown"]:
            return None
        
        # Build context string
        context_str = ""
        if call_context:
            context_str = "\nCall context: {}".format(call_context)
        
        # Show multi-choice dialog
        print("\n" + "=" * 60)
        print("UNKNOWN EXTERNAL: {}".format(func_name))
        print("=" * 60)
        if context_str:
            print(context_str)
        print("\nSelect applicable traits (comma-separated numbers, or 's' to skip):")
        
        for i, (trait, desc) in enumerate(TRAIT_DEFINITIONS.items()):
            print("  {}: {} - {}".format(i, trait, desc))
        
        # In Ghidra, use askString or askChoices
        try:
            from ghidra.util.task import ConsoleTaskMonitor
            
            # Try to use Ghidra's dialog
            choices = list(TRAIT_DEFINITIONS.keys())
            prompt = "Classify external '{}'\nSelect traits:".format(func_name)
            
            # askChoices returns list of selected items
            selected = askChoices("External Classification", prompt, choices, [])
            
            if not selected:
                self.session_skipped.add(func_name)
                return None
            
            selected_traits = list(selected)
            
        except:
            # Fallback to console input
            try:
                user_input = raw_input("\nEnter selection: ").strip()
            except NameError:
                user_input = input("\nEnter selection: ").strip()
            
            if user_input.lower() == 's' or not user_input:
                self.session_skipped.add(func_name)
                return None
            
            # Parse selection
            indices = [int(x.strip()) for x in user_input.split(',') if x.strip().isdigit()]
            trait_names = list(TRAIT_DEFINITIONS.keys())
            selected_traits = [trait_names[i] for i in indices if i < len(trait_names)]
        
        if not selected_traits:
            self.session_skipped.add(func_name)
            return None
        
        # Collect parameter indices for traits that need them
        params = {}
        for trait in selected_traits:
            if trait in PARAM_TRAITS:
                try:
                    prompt = PARAM_TRAITS[trait]
                    idx = askInt("Parameter Index", prompt)
                    params[trait] = idx
                except:
                    try:
                        idx_str = raw_input("{}: ".format(PARAM_TRAITS[trait]))
                    except NameError:
                        idx_str = input("{}: ".format(PARAM_TRAITS[trait]))
                    if idx_str.isdigit():
                        params[trait] = int(idx_str)
        
        # Save classification
        self.db.set(func_name, selected_traits, params)
        print("[+] Classified '{}' with traits: {}".format(func_name, selected_traits))
        
        return {"traits": selected_traits, "params": params}


# =============================================================================
# TAINT TRACKER WITH EXTERNAL AWARENESS
# =============================================================================

class AdaptiveTaintTracker:
    """Taint tracker that uses external classifications"""
    
    def __init__(self, extern_db, classifier):
        self.extern_db = extern_db
        self.classifier = classifier
        self.decomplib = DecompInterface()
        self.decomplib.openProgram(currentProgram)
        self.func_cache = {}
    
    def get_high_func(self, func):
        entry = func.getEntryPoint()
        if entry not in self.func_cache:
            res = self.decomplib.decompileFunction(func, 30, TaskMonitor.DUMMY)
            self.func_cache[entry] = res.getHighFunction() if res.decompileCompleted() else None
        return self.func_cache[entry]
    
    def get_call_info(self, call_op):
        """Get function name and classification for a CALL op"""
        addr_vn = call_op.getInput(0)
        if not (addr_vn and addr_vn.isAddress()):
            return None, None
        
        func = currentProgram.getListing().getFunctionAt(addr_vn.getAddress())
        if not func:
            return None, None
        
        name = func.getName()
        
        # Check if external
        if func.isExternal() or func.isThunk():
            # Get or prompt for classification
            classification = self.extern_db.get(name)
            if not classification:
                # Build context
                context = "Called at {}".format(call_op.getSeqnum().getTarget())
                classification = self.classifier.classify_external(name, context)
            
            return name, classification
        
        return name, None  # Internal function
    
    def is_taint_source(self, call_op):
        """Check if call returns tainted data"""
        name, classification = self.get_call_info(call_op)
        if classification:
            return "TAINT_RETURN" in classification.get("traits", [])
        return False
    
    def get_taint_output_param(self, call_op):
        """Get parameter index that receives tainted output, or -1"""
        name, classification = self.get_call_info(call_op)
        if classification and "TAINT_PARAM" in classification.get("traits", []):
            return classification.get("params", {}).get("TAINT_PARAM", -1)
        return -1
    
    def is_dangerous_sink(self, call_op):
        """Check if call is a dangerous sink and return sink type"""
        name, classification = self.get_call_info(call_op)
        if not classification:
            return None, None
        
        traits = classification.get("traits", [])
        params = classification.get("params", {})
        
        if "COPY_UNBOUNDED" in traits:
            return "OVERFLOW_UNBOUNDED", params.get("COPY_UNBOUNDED", 0)
        if "COPY_BOUNDED" in traits:
            return "OVERFLOW_BOUNDED", params.get("COPY_BOUNDED", 0)
        if "FORMAT_SINK" in traits:
            return "FORMAT_STRING", params.get("FORMAT_SINK", 0)
        if "FREE_PTR" in traits:
            return "FREE", params.get("FREE_PTR", 0)
        
        return None, None
    
    def trace_origin(self, varnode, depth=0):
        """Trace varnode origin with external awareness"""
        if depth > CONFIG["max_trace_depth"] or not varnode:
            return {"type": "COMPLEX", "tainted": False}
        
        if varnode.isConstant():
            return {"type": "CONST", "value": varnode.getOffset(), "tainted": False}
        
        # Check parameter
        high = varnode.getHigh()
        if high and high.getSymbol():
            sym = high.getSymbol()
            if sym.isParameter():
                return {"type": "PARAM", "name": sym.getName(), 
                        "index": sym.getCategoryIndex(), "tainted": True}
        
        def_op = varnode.getDef()
        if not def_op:
            return {"type": "INPUT", "tainted": False}
        
        opcode = def_op.getOpcode()
        
        # Handle function calls
        if opcode == PcodeOp.CALL:
            name, classification = self.get_call_info(def_op)
            
            if classification:
                traits = classification.get("traits", [])
                is_taint = "TAINT_RETURN" in traits
                is_alloc = "ALLOC_RETURN" in traits
                
                # Track allocation size for strlen-malloc correlation
                size_origin = None
                if "SIZE_FROM_PARAM" in traits:
                    size_idx = classification.get("params", {}).get("SIZE_FROM_PARAM", 0)
                    if def_op.getNumInputs() > size_idx + 1:
                        size_origin = self.trace_origin(def_op.getInput(size_idx + 1), depth + 1)
                
                return {
                    "type": "CALL",
                    "func": name,
                    "tainted": is_taint,
                    "is_alloc": is_alloc,
                    "size_origin": size_origin
                }
            
            return {"type": "CALL", "func": name or "unknown", "tainted": False}
        
        # Pass-through operations
        if opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE]:
            return self.trace_origin(def_op.getInput(0), depth + 1)
        
        # Memory load
        if opcode == PcodeOp.LOAD:
            ptr = self.trace_origin(def_op.getInput(1), depth + 1)
            return {"type": "LOAD", "ptr": ptr, "tainted": ptr.get("tainted", False)}
        
        # Pointer arithmetic
        if opcode == PcodeOp.PTRADD:
            base = self.trace_origin(def_op.getInput(0), depth + 1)
            index = self.trace_origin(def_op.getInput(1), depth + 1)
            return {
                "type": "INDEX",
                "base": base,
                "index": index,
                "tainted": base.get("tainted") or index.get("tainted", False),
                "is_alloc": base.get("is_alloc", False),
                "size_origin": base.get("size_origin")
            }
        
        if opcode == PcodeOp.PTRSUB:
            base = self.trace_origin(def_op.getInput(0), depth + 1)
            offset = def_op.getInput(1).getOffset() if def_op.getInput(1).isConstant() else 0
            return {
                "type": "FIELD",
                "base": base,
                "offset": offset,
                "tainted": base.get("tainted", False)
            }
        
        # Arithmetic - check for strlen
        if opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT]:
            left = self.trace_origin(def_op.getInput(0), depth + 1)
            right = self.trace_origin(def_op.getInput(1), depth + 1) if def_op.getNumInputs() > 1 else {}
            
            # Check for strlen in chain
            has_strlen = (left.get("func") == "strlen" or right.get("func") == "strlen" or
                         left.get("has_strlen") or right.get("has_strlen"))
            
            return {
                "type": "ARITH",
                "left": left,
                "right": right,
                "has_strlen": has_strlen,
                "tainted": left.get("tainted") or right.get("tainted", False)
            }
        
        if opcode == PcodeOp.MULTIEQUAL:
            return {"type": "PHI", "tainted": False}
        
        return {"type": "OTHER", "tainted": False}
    
    def origin_str(self, origin):
        """Convert origin to readable string"""
        if not origin:
            return "?"
        t = origin.get("type", "?")
        if t == "CONST":
            return "0x{:X}".format(origin.get("value", 0))
        if t == "PARAM":
            return origin.get("name", "param")
        if t == "CALL":
            return "ret_{}".format(origin.get("func", "?"))
        if t == "LOAD":
            return "*({})".format(self.origin_str(origin.get("ptr", {})))
        if t == "INDEX":
            return "{}[{}]".format(
                self.origin_str(origin.get("base", {})),
                self.origin_str(origin.get("index", {})))
        if t == "FIELD":
            return "{}.off_{:x}".format(
                self.origin_str(origin.get("base", {})),
                origin.get("offset", 0))
        return t


# =============================================================================
# MAIN DETECTOR
# =============================================================================

class InteractiveMemcorrDetector:
    def __init__(self):
        self.extern_db = ExternalFunctionDB(CONFIG["db_path"])
        self.classifier = ExternalClassifier(self.extern_db)
        self.tracker = AdaptiveTaintTracker(self.extern_db, self.classifier)
        self.findings = []
        self.stats = defaultdict(int)
    
    def run(self):
        print("=" * 70)
        print(" Interactive Memory Corruption Detector v3.0")
        print(" External DB: {}".format(CONFIG["db_path"]))
        print("=" * 70)
        
        funcs = list(currentProgram.getFunctionManager().getFunctions(True))
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
        
        freed_ptrs = {}
        
        for op in hf.getPcodeOps():
            if op.getOpcode() != PcodeOp.CALL:
                continue
            
            addr = op.getSeqnum().getTarget()
            
            # Check if dangerous sink
            sink_type, param_idx = self.tracker.is_dangerous_sink(op)
            
            if sink_type == "OVERFLOW_UNBOUNDED":
                self._check_unbounded_overflow(op, func, param_idx, addr)
            elif sink_type == "OVERFLOW_BOUNDED":
                self._check_bounded_overflow(op, func, param_idx, addr)
            elif sink_type == "FORMAT_STRING":
                self._check_format_string(op, func, param_idx, addr)
            elif sink_type == "FREE":
                self._check_free(op, func, freed_ptrs, param_idx, addr)
    
    def _check_unbounded_overflow(self, op, func, dst_idx, addr):
        """Check unbounded copy operations"""
        if op.getNumInputs() <= dst_idx + 1:
            return
        
        dst_vn = op.getInput(dst_idx + 1)
        dst_origin = self.tracker.trace_origin(dst_vn)
        
        # Check for strlen-malloc correlation
        if dst_origin.get("is_alloc") and dst_origin.get("size_origin", {}).get("has_strlen"):
            return  # Safe pattern
        
        # Get source if available (usually param dst_idx + 1)
        src_tainted = False
        if op.getNumInputs() > dst_idx + 2:
            src_vn = op.getInput(dst_idx + 2)
            src_origin = self.tracker.trace_origin(src_vn)
            src_tainted = src_origin.get("tainted", False)
        
        # Only report if there's actual risk
        if not src_tainted and not dst_origin.get("tainted"):
            return
        
        name, _ = self.tracker.get_call_info(op)
        details = "{}(dst={}) - unbounded copy".format(
            name, self.tracker.origin_str(dst_origin))
        if src_tainted:
            details += " [TAINTED_SRC]"
        
        self._add_finding(func.getName(), addr, "BUFFER_OVERFLOW", "HIGH", details)
    
    def _check_bounded_overflow(self, op, func, dst_idx, addr):
        """Check bounded copy operations - only flag if size is tainted"""
        # For bounded operations, primarily care about size being user-controlled
        # Most are safe unless size comes from attacker
        pass  # Skip for now - low priority
    
    def _check_format_string(self, op, func, fmt_idx, addr):
        """Check format string vulnerabilities"""
        if op.getNumInputs() <= fmt_idx + 1:
            return
        
        fmt_vn = op.getInput(fmt_idx + 1)
        fmt_origin = self.tracker.trace_origin(fmt_vn)
        
        # Skip constants
        if fmt_origin.get("type") == "CONST":
            return
        
        # Only flag if tainted
        if not fmt_origin.get("tainted"):
            return
        
        name, _ = self.tracker.get_call_info(op)
        details = "{}(fmt={}) - user-controlled format".format(
            name, self.tracker.origin_str(fmt_origin))
        
        self._add_finding(func.getName(), addr, "FORMAT_STRING", "HIGH", details)
    
    def _check_free(self, op, func, freed_ptrs, ptr_idx, addr):
        """Check double-free"""
        if op.getNumInputs() <= ptr_idx + 1:
            return
        
        ptr_vn = op.getInput(ptr_idx + 1)
        ptr_origin = self.tracker.trace_origin(ptr_vn)
        ptr_key = self.tracker.origin_str(ptr_origin)
        
        # Include field offset for differentiation
        if ptr_origin.get("type") == "FIELD":
            ptr_key = "{}.off_{:x}".format(
                self.tracker.origin_str(ptr_origin.get("base", {})),
                ptr_origin.get("offset", 0))
        
        if ptr_key in freed_ptrs:
            prev_addr = freed_ptrs[ptr_key]
            details = "double free of '{}' (first @ {})".format(ptr_key, prev_addr)
            self._add_finding(func.getName(), addr, "DOUBLE_FREE", "HIGH", details)
        else:
            freed_ptrs[ptr_key] = addr
    
    def _add_finding(self, func_name, addr, vuln_type, severity, details):
        self.findings.append({
            "func": func_name,
            "addr": str(addr),
            "type": vuln_type,
            "severity": severity,
            "details": details
        })
        self.stats[vuln_type] += 1
        self.stats[severity] += 1
        
        # Add bookmark
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
        print("\n[*] External DB: {} functions classified".format(len(self.extern_db.db)))
        
        if self.findings:
            print("\n[*] By Type:")
            for t in set(f["type"] for f in self.findings):
                print("    {}: {}".format(t, sum(1 for f in self.findings if f["type"] == t)))
            
            print("\n[!] Findings:")
            for f in self.findings[:20]:
                print("    [{}/{}] {} @ {}: {}".format(
                    f["severity"], f["type"], f["func"], f["addr"], f["details"][:50]))
        
        # Export
        try:
            out_path = os.path.join(os.path.expanduser("~"), "memcorr_v3.json")
            with open(out_path, "w") as fp:
                json.dump({"findings": self.findings, "extern_db": self.extern_db.db}, fp, indent=2)
            print("\n[*] Results: {}".format(out_path))
        except:
            pass


# =============================================================================
# UTILITY: View/Edit External DB
# =============================================================================

def view_extern_db():
    """View current external function database"""
    db = ExternalFunctionDB(CONFIG["db_path"])
    print("\n" + "=" * 60)
    print("External Function Database")
    print("=" * 60)
    print("Path: {}".format(CONFIG["db_path"]))
    print("Entries: {}".format(len(db.db)))
    print("")
    
    for name, info in sorted(db.db.items()):
        traits = info.get("traits", [])
        params = info.get("params", {})
        param_str = ", ".join("{}={}".format(k, v) for k, v in params.items())
        print("  {}: {} {}".format(name, traits, param_str if param_str else ""))


def clear_extern_db():
    """Clear external function database"""
    if os.path.exists(CONFIG["db_path"]):
        os.remove(CONFIG["db_path"])
        print("[+] Database cleared")


# =============================================================================
# RUN
# =============================================================================

def run():
    detector = InteractiveMemcorrDetector()
    detector.run()

run()