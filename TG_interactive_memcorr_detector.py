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
import threading

# =============================================================================
# EXTERNAL FUNCTION TRAITS (Multi-select categories)
# =============================================================================

TRAIT_DEFINITIONS = {
    "TAINT_RETURN": "Returns attacker data (recv, read, getenv)",
    "TAINT_PARAM": "Writes tainted data to param (fread->buf)",
    "COPY_UNBOUNDED": "Unbounded copy (strcpy, sprintf)",
    "COPY_BOUNDED": "Bounded copy (memcpy, strncpy)", 
    "FORMAT_SINK": "Format string param (printf, syslog)",
    "FREE_PTR": "Frees memory (free, realloc)",
    "ALLOC_RETURN": "Returns allocated memory (malloc)",
    "SIZE_FROM_PARAM": "Alloc size from param (malloc(p0))",
    "SAFE_IGNORE": "Safe - ignore in analysis",
}

# Parameter index prompts for traits that need them
# Index is 0-based: foo(param0, param1, param2)
#   strcpy(dst=0, src=1)
#   memcpy(dst=0, src=1, size=2)
#   printf(fmt=0, ...)
#   fprintf(file=0, fmt=1, ...)
PARAM_TRAITS = {
    "TAINT_PARAM": "Output param index (0-based, e.g. fread: buf=0)",
    "COPY_UNBOUNDED": "Dest param index (0-based, e.g. strcpy: dst=0)",
    "COPY_BOUNDED": "Dest param index (0-based, e.g. memcpy: dst=0)",
    "FORMAT_SINK": "Format param index (0-based, e.g. printf=0, fprintf=1)",
    "FREE_PTR": "Freed ptr param index (0-based, e.g. free: ptr=0)",
    "SIZE_FROM_PARAM": "Size param index (0-based, e.g. malloc: size=0)",
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
    "strncmp": {"traits": ["SAFE_IGNORE"]},
    "memcmp": {"traits": ["SAFE_IGNORE"]},
    # Fortified functions (__chk variants)
    "__strcpy_chk": {"traits": ["COPY_UNBOUNDED"], "params": {"COPY_UNBOUNDED": 0}},
    "__strcat_chk": {"traits": ["COPY_UNBOUNDED"], "params": {"COPY_UNBOUNDED": 0}},
    "__sprintf_chk": {"traits": ["COPY_UNBOUNDED", "FORMAT_SINK"], "params": {"COPY_UNBOUNDED": 0, "FORMAT_SINK": 2}},
    "__vsprintf_chk": {"traits": ["COPY_UNBOUNDED", "FORMAT_SINK"], "params": {"COPY_UNBOUNDED": 0, "FORMAT_SINK": 2}},
    "__printf_chk": {"traits": ["FORMAT_SINK"], "params": {"FORMAT_SINK": 1}},
    "__fprintf_chk": {"traits": ["FORMAT_SINK"], "params": {"FORMAT_SINK": 2}},
    "__memcpy_chk": {"traits": ["COPY_BOUNDED"], "params": {"COPY_BOUNDED": 0}},
    "__memmove_chk": {"traits": ["COPY_BOUNDED"], "params": {"COPY_BOUNDED": 0}},
    "__strncpy_chk": {"traits": ["COPY_BOUNDED"], "params": {"COPY_BOUNDED": 0}},
    "n2s": {"traits": ["TAINT_RETURN"]},  # OpenSSL macro that reads from network buffer
    "ntohs": {"traits": ["SAFE_IGNORE"]},
    "ntohl": {"traits": ["SAFE_IGNORE"]},
    "htons": {"traits": ["SAFE_IGNORE"]},
    "htonl": {"traits": ["SAFE_IGNORE"]},
    # C++ runtime/STL
    "operator.new": {"traits": ["ALLOC_RETURN"]},
    "operator.new[]": {"traits": ["ALLOC_RETURN"]},
    "operator.delete": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},
    "operator.delete[]": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},
    "_Znwm": {"traits": ["ALLOC_RETURN"]},  # operator new(size_t)
    "_Znam": {"traits": ["ALLOC_RETURN"]},  # operator new[](size_t)
    "_ZdlPv": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},  # operator delete(void*)
    "_ZdaPv": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},  # operator delete[](void*)
    "_ZdlPvm": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},  # operator delete(void*, size_t)
    "_ZdaPvm": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},  # operator delete[](void*, size_t)
    "__cxa_throw": {"traits": ["SAFE_IGNORE"]},
    "__cxa_allocate_exception": {"traits": ["ALLOC_RETURN"]},
    "__cxa_free_exception": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},
    "__cxa_begin_catch": {"traits": ["SAFE_IGNORE"]},
    "__cxa_end_catch": {"traits": ["SAFE_IGNORE"]},
    "__cxa_rethrow": {"traits": ["SAFE_IGNORE"]},
    "__cxa_guard_acquire": {"traits": ["SAFE_IGNORE"]},
    "__cxa_guard_release": {"traits": ["SAFE_IGNORE"]},
    "__gxx_personality_v0": {"traits": ["SAFE_IGNORE"]},
    "_Unwind_Resume": {"traits": ["SAFE_IGNORE"]},
    "__throw_length_error": {"traits": ["SAFE_IGNORE"]},
    "__throw_bad_alloc": {"traits": ["SAFE_IGNORE"]},
    "__throw_out_of_range": {"traits": ["SAFE_IGNORE"]},
    "_M_dispose": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},
    "_M_destroy": {"traits": ["FREE_PTR"], "params": {"FREE_PTR": 0}},
    "_M_create": {"traits": ["ALLOC_RETURN"]},
    "getsockname": {"traits": ["SAFE_IGNORE"]},
    "getsockopt": {"traits": ["SAFE_IGNORE"]},
    # Common libc functions that are safe to ignore
    "__libc_start_main": {"traits": ["SAFE_IGNORE"]},
    "__cxa_finalize": {"traits": ["SAFE_IGNORE"]},
    "__cxa_atexit": {"traits": ["SAFE_IGNORE"]},
    "__stack_chk_fail": {"traits": ["SAFE_IGNORE"]},
    "__gmon_start__": {"traits": ["SAFE_IGNORE"]},
    "_ITM_registerTMCloneTable": {"traits": ["SAFE_IGNORE"]},
    "_ITM_deregisterTMCloneTable": {"traits": ["SAFE_IGNORE"]},
    "exit": {"traits": ["SAFE_IGNORE"]},
    "_exit": {"traits": ["SAFE_IGNORE"]},
    "abort": {"traits": ["SAFE_IGNORE"]},
    "atexit": {"traits": ["SAFE_IGNORE"]},
    "close": {"traits": ["SAFE_IGNORE"]},
    "open": {"traits": ["TAINT_RETURN"]},
    "fopen": {"traits": ["TAINT_RETURN"]},
    "fclose": {"traits": ["SAFE_IGNORE"]},
    "socket": {"traits": ["TAINT_RETURN"]},
    "accept": {"traits": ["TAINT_RETURN"]},
    "recvfrom": {"traits": ["TAINT_RETURN", "TAINT_PARAM"], "params": {"TAINT_PARAM": 1}},
    "recvmsg": {"traits": ["TAINT_RETURN", "TAINT_PARAM"], "params": {"TAINT_PARAM": 1}},
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
# INTERACTIVE DIALOG (Non-modal Swing UI)
# =============================================================================

class ExternalClassifierUI:
    """Non-modal UI for classifying externals - doesn't block Ghidra"""
    
    def __init__(self, db, pending_list):
        from javax.swing import (JFrame, JPanel, JButton, JLabel, 
                                  JScrollPane, JCheckBox, JSpinner, SpinnerNumberModel,
                                  BorderFactory, WindowConstants)
        from javax.swing.border import EmptyBorder
        from java.awt import BorderLayout, FlowLayout, GridLayout, Dimension
        
        self.db = db
        self.pending = list(pending_list)
        self.current_idx = 0
        self.skipped = set()
        self.is_done = False
        
        if not self.pending:
            print("[*] No unknown externals to classify")
            self.is_done = True
            return
        
        # Build UI
        self.frame = JFrame("Classify External Functions ({} remaining)".format(len(self.pending)))
        self.frame.setSize(550, 500)
        self.frame.setLocationRelativeTo(None)
        self.frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
        
        # Main panel
        main_panel = JPanel(BorderLayout(10, 10))
        main_panel.setBorder(EmptyBorder(10, 10, 10, 10))
        
        # Function name label
        self.func_label = JLabel()
        self.func_label.setBorder(EmptyBorder(5, 5, 5, 5))
        main_panel.add(self.func_label, BorderLayout.NORTH)
        
        # Checkboxes for traits
        traits_panel = JPanel(GridLayout(0, 1, 5, 5))
        traits_panel.setBorder(BorderFactory.createTitledBorder("Select Traits"))
        
        self.trait_checks = {}
        self.param_spinners = {}
        
        for trait, desc in TRAIT_DEFINITIONS.items():
            row = JPanel(FlowLayout(FlowLayout.LEFT))
            cb = JCheckBox("{} - {}".format(trait, desc))
            self.trait_checks[trait] = cb
            row.add(cb)
            
            if trait in PARAM_TRAITS:
                spinner = JSpinner(SpinnerNumberModel(0, 0, 10, 1))
                spinner.setPreferredSize(Dimension(50, 25))
                self.param_spinners[trait] = spinner
                row.add(JLabel("param:"))
                row.add(spinner)
            
            traits_panel.add(row)
        
        scroll = JScrollPane(traits_panel)
        main_panel.add(scroll, BorderLayout.CENTER)
        
        # Buttons - store references
        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        self.skip_all_btn = JButton("Skip All Remaining")
        self.skip_btn = JButton("Skip")
        self.save_btn = JButton("Save & Next")
        
        btn_panel.add(self.skip_all_btn)
        btn_panel.add(self.skip_btn)
        btn_panel.add(self.save_btn)
        main_panel.add(btn_panel, BorderLayout.SOUTH)
        
        self.frame.add(main_panel)
        self._show_current()
        self.frame.setVisible(True)
        
        # Wire up button actions using lambda-style approach
        self._setup_listeners()
    
    def _setup_listeners(self):
        """Setup button listeners using JProxy"""
        import jpype
        from java.awt.event import ActionListener
        
        ui = self
        
        def skip_action(e):
            ui._skip_current()
        
        def save_action(e):
            ui._save_current()
        
        def skip_all_action(e):
            ui._skip_all()
        
        self.skip_btn.addActionListener(jpype.JProxy(ActionListener, dict={'actionPerformed': skip_action}))
        self.save_btn.addActionListener(jpype.JProxy(ActionListener, dict={'actionPerformed': save_action}))
        self.skip_all_btn.addActionListener(jpype.JProxy(ActionListener, dict={'actionPerformed': skip_all_action}))
    
    def _show_current(self):
        if self.current_idx >= len(self.pending):
            self._finish()
            return
        
        func_name, context = self.pending[self.current_idx]
        remaining = len(self.pending) - self.current_idx
        self.frame.setTitle("Classify External Functions ({} remaining)".format(remaining))
        
        ctx_str = " ({})".format(context) if context else ""
        self.func_label.setText("<html><b>{}</b>{}</html>".format(func_name, ctx_str))
        
        for cb in self.trait_checks.values():
            cb.setSelected(False)
        for sp in self.param_spinners.values():
            sp.setValue(0)
    
    def _save_current(self):
        func_name, _ = self.pending[self.current_idx]
        
        selected_traits = []
        params = {}
        
        for trait, cb in self.trait_checks.items():
            if cb.isSelected():
                selected_traits.append(trait)
                if trait in self.param_spinners:
                    params[trait] = int(self.param_spinners[trait].getValue())
        
        if selected_traits:
            self.db.set(func_name, selected_traits, params)
            print("[+] Classified '{}': {}".format(func_name, selected_traits))
        else:
            self.skipped.add(func_name)
        
        self.current_idx += 1
        self._show_current()
    
    def _skip_current(self):
        func_name, _ = self.pending[self.current_idx]
        self.skipped.add(func_name)
        self.current_idx += 1
        self._show_current()
    
    def _skip_all(self):
        for i in range(self.current_idx, len(self.pending)):
            self.skipped.add(self.pending[i][0])
        self._finish()
    
    def _finish(self):
        self.is_done = True
        self.frame.dispose()
        print("[*] Classification complete. {} skipped.".format(len(self.skipped)))
        
        # Add skipped functions to classifier's session_skipped to prevent blocking dialogs
        if hasattr(self, 'classifier_ref') and self.classifier_ref:
            self.classifier_ref.session_skipped.update(self.skipped)
        
        # Run the analysis callback if provided
        if hasattr(self, 'on_finish') and self.on_finish:
            self.on_finish()


class ExternalClassifier:
    """Handles interactive classification of unknown externals with async support"""
    
    def __init__(self, db):
        self.db = db
        self.session_skipped = set()
        self.pending_queue = []
        self.pending_set = set()
        self.classification_lock = threading.Lock()
        self.batch_mode = False
    
    def queue_for_classification(self, func_name, call_context=None):
        """Queue an external for later batch classification"""
        if func_name in self.session_skipped or func_name in self.pending_set:
            return None
        
        existing = self.db.get(func_name)
        if existing:
            return existing
        
        with self.classification_lock:
            if func_name not in self.pending_set:
                self.pending_queue.append((func_name, call_context))
                self.pending_set.add(func_name)
        return None
    
    def classify_external(self, func_name, call_context=None):
        """Classify an external - queue it in batch mode"""
        if func_name in self.session_skipped:
            return None
        
        existing = self.db.get(func_name)
        if existing:
            return existing
        
        if self.batch_mode:
            return self.queue_for_classification(func_name, call_context)
        
        if not CONFIG["prompt_on_unknown"]:
            return None
        
        # Fallback to blocking dialog if not in batch mode
        return self._show_blocking_dialog(func_name, call_context)
    
    def _show_blocking_dialog(self, func_name, call_context=None):
        """Fallback blocking dialog"""
        from java.util import ArrayList
        
        trait_keys = list(TRAIT_DEFINITIONS.keys())
        choices = ArrayList()
        for trait, desc in TRAIT_DEFINITIONS.items():
            choices.add("{} - {}".format(trait, desc))
        
        prompt = "Unknown external: '{}'".format(func_name)
        
        try:
            selected = askChoices("Classify External", prompt, choices)
        except:
            self.session_skipped.add(func_name)
            return None
        
        if not selected:
            self.session_skipped.add(func_name)
            return None
        
        selected_traits = [str(s).split(" - ")[0] for s in selected if str(s).split(" - ")[0] in trait_keys]
        if not selected_traits:
            return None
        
        params = {}
        for trait in selected_traits:
            if trait in PARAM_TRAITS:
                try:
                    idx = askInt("Param Index", PARAM_TRAITS[trait])
                    if idx is not None:
                        params[trait] = idx
                except:
                    pass
        
        self.db.set(func_name, selected_traits, params)
        return {"traits": selected_traits, "params": params}
    
    def show_classification_ui(self, on_finish=None):
        """Show non-modal UI for batch classification, returns UI instance"""
        pending = list(self.pending_queue)
        self.pending_queue = []
        self.pending_set = set()
        
        if not pending:
            if on_finish:
                on_finish()
            return None
        
        ui = ExternalClassifierUI(self.db, pending)
        ui.on_finish = on_finish
        ui.classifier_ref = self  # Reference to sync skipped set
        return ui
    
    def get_pending_count(self):
        return len(self.pending_queue)


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
        
        # Memory load - reading from tainted pointer means data is tainted
        if opcode == PcodeOp.LOAD:
            ptr = self.trace_origin(def_op.getInput(1), depth + 1)
            # Data loaded from a tainted pointer is tainted (e.g., reading size from network buffer)
            is_tainted = ptr.get("tainted", False)
            return {"type": "LOAD", "ptr": ptr, "tainted": is_tainted}
        
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
        
        # Arithmetic - check for strlen and propagate taint
        if opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT,
                      PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT,
                      PcodeOp.INT_OR, PcodeOp.INT_AND, PcodeOp.INT_XOR]:
            left = self.trace_origin(def_op.getInput(0), depth + 1)
            right = self.trace_origin(def_op.getInput(1), depth + 1) if def_op.getNumInputs() > 1 else {}
            
            # Check for strlen in chain
            has_strlen = (left.get("func") == "strlen" or right.get("func") == "strlen" or
                         left.get("has_strlen") or right.get("has_strlen"))
            
            # Taint propagates through arithmetic (e.g., byte-swapping size field)
            is_tainted = left.get("tainted") or right.get("tainted", False)
            
            return {
                "type": "ARITH",
                "left": left,
                "right": right,
                "has_strlen": has_strlen,
                "tainted": is_tainted
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
        self.funcs = []
    
    def run(self, two_phase=True):
        """
        Run analysis. If two_phase=True, first collect all unknown externals,
        then show non-modal UI for classification. Analysis runs after UI closes.
        """
        print("=" * 70)
        print(" Interactive Memory Corruption Detector v3.0")
        print(" External DB: {}".format(CONFIG["db_path"]))
        print(" Mode: {}".format("Two-Phase (Non-blocking)" if two_phase else "Interactive"))
        print("=" * 70)
        
        self.funcs = list(currentProgram.getFunctionManager().getFunctions(True))
        print("[*] Analyzing {} functions...".format(len(self.funcs)))
        
        if two_phase:
            # Phase 1: Collect unknown externals
            print("\n[Phase 1] Scanning for unknown externals...")
            self.classifier.batch_mode = True
            for i, func in enumerate(self.funcs):
                if func.isThunk() or func.isExternal():
                    continue
                if (i + 1) % 200 == 0:
                    print("    {}/{} ({} unknowns queued)".format(
                        i + 1, len(self.funcs), self.classifier.get_pending_count()))
                self._scan_for_externals(func)
            
            pending_count = self.classifier.get_pending_count()
            if pending_count > 0:
                print("\n[Phase 2] Found {} unknown externals.".format(pending_count))
                print("          Classify in the window, then analysis runs automatically.")
                print("          You can freely browse code while the window is open.\n")
                
                self.classifier.batch_mode = False
                # Show UI - analysis will run when UI finishes
                self.classifier.show_classification_ui(on_finish=self._run_analysis)
                return self.findings  # Return immediately, analysis runs async
            
            print("\n[*] No unknown externals - running analysis directly...")
        
        # Run analysis directly if no UI needed
        self._run_analysis()
        return self.findings
    
    def _run_analysis(self):
        """Run the actual vulnerability analysis (Phase 3)"""
        print("\n[Phase 3] Running analysis with classifications...")
        
        self.classifier.batch_mode = False
        self.tracker.func_cache.clear()
        
        for i, func in enumerate(self.funcs):
            if func.isThunk() or func.isExternal():
                continue
            if (i + 1) % 200 == 0:
                print("    {}/{}".format(i + 1, len(self.funcs)))
            self._analyze_function(func)
        
        self._summarize()
    
    def _scan_for_externals(self, func):
        """Scan function for external calls to queue for classification"""
        hf = self.tracker.get_high_func(func)
        if not hf:
            return
        
        for op in hf.getPcodeOps():
            if op.getOpcode() != PcodeOp.CALL:
                continue
            # This will queue unknowns when batch_mode=True
            self.tracker.get_call_info(op)
    
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
            
            # Check for integer overflow in allocation
            self._check_alloc_overflow(op, func, addr)
    
    def _check_unbounded_overflow(self, op, func, dst_idx, addr):
        """Check unbounded copy operations"""
        if op.getNumInputs() <= dst_idx + 1:
            return
        
        dst_vn = op.getInput(dst_idx + 1)
        dst_origin = self.tracker.trace_origin(dst_vn)
        
        # Check for strlen-malloc pattern - this is DANGEROUS (off-by-one)
        # malloc(strlen(s)) + strcpy = overflow because strlen doesn't include null
        if dst_origin.get("is_alloc") and dst_origin.get("size_origin", {}).get("has_strlen"):
            name, _ = self.tracker.get_call_info(op)
            details = "{}(dst={}) - malloc(strlen()) off-by-one".format(
                name, self.tracker.origin_str(dst_origin))
            self._add_finding(func.getName(), addr, "HEAP_OFF_BY_ONE", "HIGH", details)
            return
        
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
        """Check bounded copy operations - flag if size comes from attacker input"""
        if op.getNumInputs() <= dst_idx + 1:
            return
        
        name, classification = self.tracker.get_call_info(op)
        if not classification:
            return
        
        # For bounded copies, check if size parameter is tainted
        # This catches heartbleed-style bugs: memcpy(dst, src, attacker_size)
        size_idx = 2  # Default for memcpy(dst, src, size)
        
        if op.getNumInputs() > size_idx + 1:
            size_vn = op.getInput(size_idx + 1)
            size_origin = self.tracker.trace_origin(size_vn)
            
            # Check for strlen-based size (off-by-one)
            if size_origin.get("has_strlen") or size_origin.get("func") == "strlen":
                dst_vn = op.getInput(dst_idx + 1)
                dst_origin = self.tracker.trace_origin(dst_vn)
                details = "{}(dst={}, size=strlen()) - potential off-by-one".format(
                    name, self.tracker.origin_str(dst_origin))
                self._add_finding(func.getName(), addr, "HEAP_OFF_BY_ONE", "MEDIUM", details)
                return
            
            # Check for tainted size from LOAD (heartbleed pattern)
            # Only flag if size is derived from reading memory (not just parameter arithmetic)
            # This avoids false positives on STL internal functions
            if size_origin.get("type") == "LOAD" and size_origin.get("tainted"):
                details = "{}(size={}) - size read from attacker-controlled buffer".format(
                    name, self.tracker.origin_str(size_origin))
                self._add_finding(func.getName(), addr, "TAINTED_SIZE_OVERREAD", "HIGH", details)
                return
            
            # Check nested - size from arithmetic on LOAD
            if size_origin.get("type") == "ARITH":
                left = size_origin.get("left", {})
                right = size_origin.get("right", {})
                # Look for LOAD in the operands
                if ((left.get("type") == "LOAD" and left.get("tainted")) or
                    (right.get("type") == "LOAD" and right.get("tainted"))):
                    details = "{}(size={}) - size derived from attacker buffer".format(
                        name, self.tracker.origin_str(size_origin))
                    self._add_finding(func.getName(), addr, "TAINTED_SIZE_OVERREAD", "HIGH", details)
    
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
    
    def _check_alloc_overflow(self, op, func, addr):
        """Check for integer overflow in allocation size (malloc(a*b*c) pattern)"""
        name, classification = self.tracker.get_call_info(op)
        if not classification:
            return
        
        traits = classification.get("traits", [])
        params = classification.get("params", {})
        
        # Only check allocation functions
        if "ALLOC_RETURN" not in traits or "SIZE_FROM_PARAM" not in traits:
            return
        
        size_idx = params.get("SIZE_FROM_PARAM", 0)
        if op.getNumInputs() <= size_idx + 1:
            return
        
        size_vn = op.getInput(size_idx + 1)
        size_origin = self.tracker.trace_origin(size_vn)
        
        # Check if size comes from multiplication of tainted values
        if size_origin.get("type") == "ARITH" and size_origin.get("tainted"):
            # Look for multiplication pattern with tainted operands
            left = size_origin.get("left", {})
            right = size_origin.get("right", {})
            
            # Count tainted operands in multiplication chain
            tainted_factors = self._count_tainted_factors(size_origin)
            
            if tainted_factors >= 2:
                details = "{}(size={}) - {} tainted factors multiplied, no overflow check".format(
                    name, self.tracker.origin_str(size_origin), tainted_factors)
                self._add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC", "HIGH", details)
            elif tainted_factors == 1 and self._has_multiplication(size_origin):
                # Single tainted factor in multiplication - still risky
                details = "{}(size={}) - tainted value in size calculation".format(
                    name, self.tracker.origin_str(size_origin))
                self._add_finding(func.getName(), addr, "INTEGER_OVERFLOW_ALLOC", "MEDIUM", details)
    
    def _count_tainted_factors(self, origin, depth=0):
        """Count tainted factors in a multiplication chain"""
        if depth > 8 or not origin:
            return 0
        
        if origin.get("type") == "ARITH":
            left = origin.get("left", {})
            right = origin.get("right", {})
            return self._count_tainted_factors(left, depth+1) + self._count_tainted_factors(right, depth+1)
        
        if origin.get("tainted"):
            return 1
        return 0
    
    def _has_multiplication(self, origin, depth=0):
        """Check if origin involves multiplication"""
        if depth > 8 or not origin:
            return False
        
        if origin.get("type") == "ARITH":
            # Check if this is multiplication (we track all arith the same, so assume yes if nested)
            left = origin.get("left", {})
            right = origin.get("right", {})
            if left.get("type") == "ARITH" or right.get("type") == "ARITH":
                return True
            if left.get("tainted") and right.get("type") != "CONST":
                return True
            if right.get("tainted") and left.get("type") != "CONST":
                return True
        return False
    
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
