# Auto Class Recoverer v47 (Null-Safety Fix for HighVariables)
# @category C++
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.data import (
    StructureDataType, PointerDataType, VoidDataType, 
    IntegerDataType, CharDataType, BooleanDataType, DataTypeConflictHandler,
    Undefined1DataType, FunctionDefinitionDataType, CategoryPath
)
from ghidra.program.model.symbol import SourceType, RefType
from ghidra.program.model.listing import ParameterImpl, Function
from java.util import ArrayList 

# -----------------------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------------------
CREATE_STRUCT = True       
CASCADE_ANALYSIS = True    
DEBUG_MODE = True          
MINE_VTABLE = True         
MAX_STRUCT_SIZE = 0x10000  # 64KB Safety Cap

class ClassRecoverer:
    def __init__(self, func):
        self.func = func
        self.fields = {} 
        self.class_size = 0
        self.vn_map = {} 
        self.struct_name = "Class_{}".format(func.getName())
        self.vtable_addr = None
        self.vtable_struct = None
        self.parent_struct = None
        self.ptr_size = currentProgram.getDefaultPointerSize()
        self.derived_candidates = []
        self.vtable_offset = -1
        self.is_constructor = False

        fname = func.getName(True)
        if "::" in fname:
            parts = fname.split("::")
            if len(parts) >= 2: 
                self.struct_name = parts[-2]
                func_simple = parts[-1]
                if func_simple == self.struct_name: self.is_constructor = True

    def log(self, msg, indent=0):
        if DEBUG_MODE: 
            prefix = "  " * indent
            print("[Log] " + prefix + msg)

    def analyze(self):
        print("\n" + "="*60)
        print(" ANALYZING: {}".format(self.func.getName()))
        print("="*60)
        
        decomplib = DecompInterface()
        decomplib.openProgram(currentProgram)
        res = decomplib.decompileFunction(self.func, 30, TaskMonitor.DUMMY)
        if not res.decompileCompleted(): return []

        high_func = res.getHighFunction()
        sym_map = high_func.getLocalSymbolMap()
        if sym_map.getNumParams() < 1: 
            if CASCADE_ANALYSIS: self.force_cascade()
            return self.derived_candidates
            
        this_sym = sym_map.getParamSymbol(0)
        
        # --- FIX: Null-Safe HighVariable Check ---
        this_hv = this_sym.getHighVariable()
        if this_hv is None:
            self.log("[!] Warning: No HighVariable for 'this'. Decompiler sync issue or static func.", 1)
            # We can't track 'this', but we can still cascade if it's a constructor pattern
            if CASCADE_ANALYSIS: self.force_cascade()
            return self.derived_candidates
            
        this_vn = this_hv.getRepresentative()
        
        self.log("Identified 'this': {} (Storage: {})".format(this_vn, this_sym.getStorage()))
        self.vn_map[this_vn] = 0 

        ops = list(high_func.getPcodeOps())
        
        if self.is_constructor:
            self.detect_inheritance(ops, this_vn)

        changes = True
        pass_count = 0
        while changes and pass_count < 10:
            changes = False
            pass_count += 1
            for op in ops:
                if self.process_op(op): changes = True

        for op in ops:
            self.scan_access(op)

        if self.vtable_addr:
            self.recover_vtable_struct()
            self.rename_vtable_symbol()
            
            if MINE_VTABLE:
                self.mine_vtable_for_types()

        struct_dt = self.create_class_struct()
        
        if struct_dt:
            self.update_function_signature(self.func, struct_dt)
            if CASCADE_ANALYSIS:
                self.find_derived_constructors(this_sym.getStorage())
                
        return self.derived_candidates

    def process_op(self, op):
        opcode = op.getOpcode()
        out_vn = op.getOutput()
        if not out_vn: return False
        if out_vn in self.vn_map: return False 

        in0 = op.getInput(0)
        base = self.vn_map.get(in0)
        if base is None: return False

        new_offset = None
        if opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE]:
            new_offset = base
        elif opcode in [PcodeOp.PTRADD, PcodeOp.INT_ADD]:
            in1 = op.getInput(1)
            if in1.isConstant():
                add = in1.getOffset()
                stride = 1
                if opcode == PcodeOp.PTRADD:
                    in2 = op.getInput(2)
                    if in2: stride = in2.getOffset()
                new_offset = base + (add * stride)

        if new_offset is not None:
            if new_offset > MAX_STRUCT_SIZE: return False
            self.vn_map[out_vn] = new_offset
            return True
        return False

    def scan_access(self, op):
        opcode = op.getOpcode()
        if opcode == PcodeOp.STORE:
            ptr_vn = op.getInput(1)
            val_vn = op.getInput(2)
            offset = self.vn_map.get(ptr_vn)
            
            if offset is not None:
                if offset > MAX_STRUCT_SIZE: return

                if (offset == 0 or offset == self.vtable_offset) and self.is_constructor:
                    vtable = self.resolve_via_references(op)
                    if not vtable:
                        origin = self.trace_value_origin(val_vn)
                        vtable = self.resolve_global_addr(origin)

                    if vtable and self.validate_vtable(vtable):
                        print("[!] VTable Found at +0x{:x} -> {}".format(offset, vtable))
                        self.vtable_addr = vtable
                        self.vtable_offset = offset
                        return

                if offset == self.vtable_offset: return
                dt = self.infer_type(val_vn)
                self.add_field(offset, dt)

        elif opcode == PcodeOp.LOAD:
            ptr_vn = op.getInput(1)
            offset = self.vn_map.get(ptr_vn)
            if offset is not None:
                if offset > MAX_STRUCT_SIZE: return
                if offset == self.vtable_offset: return 
                dt = self.infer_type(op.getOutput())
                self.add_field(offset, dt)

    def force_cascade(self):
        print("[*] Forced Cascade (Constructor Mode)...")
        refs = currentProgram.getReferenceManager().getReferencesTo(self.func.getEntryPoint())
        for ref in refs:
            if not ref.getReferenceType().isCall(): continue
            caller = currentProgram.getListing().getFunctionContaining(ref.getFromAddress())
            if not caller: continue
            if caller.getEntryPoint() == self.func.getEntryPoint(): continue
            print("    [Domino] Adding candidate: {}".format(caller.getName()))
            self.derived_candidates.append(caller)

    def find_derived_constructors(self, target_storage):
        self.log("Scanning for Derived Classes...", 1)
        refs = currentProgram.getReferenceManager().getReferencesTo(self.func.getEntryPoint())
        
        for ref in refs:
            if not ref.getReferenceType().isCall(): continue
            caller = currentProgram.getListing().getFunctionContaining(ref.getFromAddress())
            if not caller: continue
            if caller.getEntryPoint() == self.func.getEntryPoint(): continue
            
            # HEURISTIC 1: Name match
            cname = caller.getName(True)
            if "::" in cname:
                parts = cname.split("::")
                if len(parts) >= 2 and parts[-1] == parts[-2]:
                    print("    [Cascade] ACCEPT: Heuristic Match -> {}".format(caller.getName()))
                    self.derived_candidates.append(caller)
                    continue 
            
            # HEURISTIC 2: Variable Propagation
            decomplib = DecompInterface()
            decomplib.openProgram(currentProgram)
            res = decomplib.decompileFunction(caller, 30, TaskMonitor.DUMMY)
            if not res.decompileCompleted(): continue
            
            hf = res.getHighFunction()
            sym_map = hf.getLocalSymbolMap()
            if sym_map.getNumParams() < 1: continue
            
            caller_storage = sym_map.getParamSymbol(0).getStorage()
            
            ops = hf.getPcodeOps(ref.getFromAddress())
            found_pass = False
            while ops.hasNext():
                op = ops.next()
                if op.getOpcode() == PcodeOp.CALL and op.getInput(0).getAddress() == self.func.getEntryPoint():
                    if op.getNumInputs() > 1:
                        passed_vn = op.getInput(1)
                        passed_high = passed_vn.getHigh()
                        if passed_high and passed_high.getSymbol():
                            p_storage = passed_high.getSymbol().getStorage()
                            if p_storage == caller_storage:
                                print("    [Cascade] ACCEPT: Propagation -> {}".format(caller.getName()))
                                self.derived_candidates.append(caller)
                                found_pass = True
                                break

    def mine_vtable_for_types(self):
        print("[*] Mining VTable functions for field types...")
        mem = currentProgram.getMemory()
        listing = currentProgram.getListing()
        curr = self.vtable_addr
        
        for i in range(15):
            try:
                ptr_val = mem.getInt(curr) if self.ptr_size == 4 else mem.getLong(curr)
                if ptr_val == 0: break
                
                func_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(ptr_val)
                func = listing.getFunctionAt(func_addr)
                
                if func and not func.isThunk():
                    self.scan_virtual_function(func)
                else:
                    self.log("    Skipping empty/thunk func at index {}".format(i), 1)
                
                curr = curr.add(self.ptr_size)
            except: break

    def scan_virtual_function(self, func):
        decomplib = DecompInterface()
        decomplib.openProgram(currentProgram)
        res = decomplib.decompileFunction(func, 10, TaskMonitor.DUMMY)
        if not res.decompileCompleted(): return
        
        hf = res.getHighFunction()
        sym_map = hf.getLocalSymbolMap()
        if sym_map.getNumParams() < 1: return
        
        this_hv = sym_map.getParamSymbol(0).getHighVariable()
        if not this_hv: return # Safety check
        this_vn = this_hv.getRepresentative()
        
        local_map = {this_vn: 0}
        
        ops = list(hf.getPcodeOps())
        for _ in range(5):
            for op in ops:
                out = op.getOutput()
                if not out or out in local_map: continue
                in0 = op.getInput(0)
                if in0 in local_map:
                    base = local_map[in0]
                    opc = op.getOpcode()
                    if opc in [PcodeOp.COPY, PcodeOp.CAST]: local_map[out] = base
                    elif opc == PcodeOp.PTRADD:
                        in1 = op.getInput(1)
                        if in1.isConstant(): local_map[out] = base + in1.getOffset() * op.getInput(2).getOffset()

        for op in ops:
            if op.getOpcode() == PcodeOp.LOAD:
                ptr = op.getInput(1)
                if ptr in local_map:
                    offset = local_map[ptr]
                    if offset > MAX_STRUCT_SIZE: continue
                    out = op.getOutput()
                    self.check_usage(out, offset)

    def check_usage(self, varnode, offset):
        if not varnode: return
        try:
            descendants = varnode.getDescendants()
            for op in descendants:
                opc = op.getOpcode()
                if opc == PcodeOp.CALL:
                    target = op.getInput(0).getAddress()
                    callee = currentProgram.getListing().getFunctionAt(target)
                    if callee:
                        name = callee.getName().lower()
                        if "str" in name or "print" in name:
                            self.add_field(offset, PointerDataType(CharDataType.dataType))
                if opc == PcodeOp.LOAD:
                    if op.getInput(1) == varnode:
                        if offset in self.fields:
                            curr = self.fields[offset]
                            if isinstance(curr, (IntegerDataType, Undefined1DataType)):
                                self.add_field(offset, PointerDataType(VoidDataType.dataType))
        except: pass

    # ... [Helpers] ...
    def resolve_via_references(self, pcode_op):
        seq = pcode_op.getSeqnum()
        if not seq: return None
        addr = seq.getTarget()
        refs = currentProgram.getReferenceManager().getReferencesFrom(addr)
        for ref in refs:
            if ref.getReferenceType().isData(): return ref.getToAddress()
        return None

    def validate_vtable(self, addr):
        mem = currentProgram.getMemory()
        block = mem.getBlock(addr)
        if not block: return False
        sym = currentProgram.getSymbolTable().getPrimarySymbol(addr)
        if sym:
            name = sym.getName()
            if "PTR_" in name or "vtable" in name or "TV" in name: return True
        curr = addr
        for _ in range(1):
            try:
                val = mem.getInt(curr) if self.ptr_size == 4 else mem.getLong(curr)
                if val == 0: return False
                target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(val)
                if currentProgram.getListing().getFunctionAt(target): return True
                blk = mem.getBlock(target)
                if blk and blk.isExecute(): return True
            except: break
        return False

    def trace_value_origin(self, varnode):
        curr = varnode
        for i in range(10): 
            if not curr: break
            if curr.isConstant() or curr.isAddress(): return curr
            def_op = curr.getDef()
            if not def_op: break
            opc = def_op.getOpcode()
            if opc in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.PTRSUB]:
                curr = def_op.getInput(0) if opc != PcodeOp.PTRSUB else curr
                if opc == PcodeOp.PTRSUB: return curr
            elif opc == PcodeOp.INT_ADD:
                in0 = def_op.getInput(0)
                in1 = def_op.getInput(1)
                if in1.isConstant() and in1.getOffset() == 0: curr = in0
                elif in0.isConstant() and in0.getOffset() == 0: curr = in1
                else: return curr 
            else: break
        return curr

    def resolve_global_addr(self, varnode):
        if varnode.isAddress(): return varnode.getAddress()
        if varnode.isConstant():
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(varnode.getOffset())
        def_op = varnode.getDef()
        if not def_op: return None
        if def_op.getOpcode() == PcodeOp.PTRSUB:
            in1 = def_op.getInput(1)
            if in1.isConstant():
                return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(in1.getOffset())
        if def_op.getOpcode() == PcodeOp.INT_ADD:
            in0 = def_op.getInput(0)
            in1 = def_op.getInput(1)
            base = self.resolve_global_addr(in0)
            if not base: base = self.resolve_global_addr(in1)
            offset = 0
            if in1.isConstant(): offset = in1.getOffset()
            elif in0.isConstant(): offset = in0.getOffset()
            if base: return base.add(offset)
        return None

    def recover_vtable_struct(self):
        print("[+] Recovering VTable Data...")
        dtm = currentProgram.getDataTypeManager()
        mem = currentProgram.getMemory()
        listing = currentProgram.getListing()
        vname = "VTable_{}".format(self.struct_name)
        vtable_struct = StructureDataType(vname, 0)
        curr_addr = self.vtable_addr
        for i in range(50): 
            try:
                ptr_val = mem.getInt(curr_addr) if self.ptr_size == 4 else mem.getLong(curr_addr)
                if ptr_val == 0: break
                func_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(ptr_val)
                func = listing.getFunctionAt(func_addr)
                fname = "func_{:02d}".format(i)
                if func:
                    raw = func.getName(True)
                    fname = raw.split("::")[-1] if "::" in raw else func.getName()
                vtable_struct.add(PointerDataType(VoidDataType.dataType), self.ptr_size, fname, "Virtual Function")
                curr_addr = curr_addr.add(self.ptr_size)
            except: break
        self.vtable_struct = dtm.addDataType(vtable_struct, DataTypeConflictHandler.REPLACE_HANDLER)
        if self.vtable_offset >= 0:
            self.fields[self.vtable_offset] = PointerDataType(self.vtable_struct)

    def rename_vtable_symbol(self):
        if not self.vtable_addr: return
        new_name = "vtable_data_{}".format(self.struct_name)
        try:
            sym_tab = currentProgram.getSymbolTable()
            curr_sym = sym_tab.getPrimarySymbol(self.vtable_addr)
            if curr_sym:
                if curr_sym.getName() != new_name:
                    curr_sym.setName(new_name, SourceType.USER_DEFINED)
            else:
                sym_tab.createLabel(self.vtable_addr, new_name, SourceType.USER_DEFINED)
        except: pass

    def infer_type(self, varnode):
        if not varnode: return None
        high = varnode.getHigh()
        if high and high.getDataType():
            dt = high.getDataType()
            if "undefined" not in dt.getName().lower(): return dt
        size = varnode.getSize()
        if size == 1: return CharDataType.dataType
        if size == 4: return IntegerDataType.dataType 
        if size == 8: return PointerDataType(VoidDataType.dataType)
        return IntegerDataType.dataType

    def add_field(self, offset, dt):
        if offset in self.fields: return 
        if dt is None: dt = PointerDataType(VoidDataType.dataType)
        length = dt.getLength()
        if length > 1:
            keys_to_remove = []
            for i in range(1, length):
                if (offset + i) in self.fields:
                    if self.fields[offset+i].getLength() == 1: keys_to_remove.append(offset+i)
            for k in keys_to_remove: self.fields.pop(k)
        self.fields[offset] = dt
        end = offset + length
        if end > self.class_size: self.class_size = end

    def detect_inheritance(self, ops, this_vn):
        dtm = currentProgram.getDataTypeManager()
        for op in ops:
            if op.getOpcode() == PcodeOp.CALL:
                if op.getNumInputs() > 1:
                    arg1 = op.getInput(1)
                    if arg1 == this_vn:
                        call_addr = op.getInput(0).getAddress()
                        parent_func = currentProgram.getListing().getFunctionAt(call_addr)
                        if parent_func:
                            pname = parent_func.getName(True)
                            if "::" in pname:
                                pclass = pname.split("::")[-2]
                                if pclass == self.struct_name: continue
                                it = dtm.getAllStructures()
                                while it.hasNext():
                                    st = it.next()
                                    if st.getName() == pclass:
                                        self.parent_struct = st
                                        print("[+] Inheritance: Base '{}'".format(st.getName()))
                                        return

    def find_target_struct(self, dtm):
        candidates = []
        all_structs = dtm.getAllStructures()
        while all_structs.hasNext():
            st = all_structs.next()
            if st.getName() == self.struct_name: candidates.append(st)
        if not candidates: return None
        best = candidates[0]
        for c in candidates:
            if "Demangler" in c.getCategoryPath().getPath(): best = c
        return best

    def create_class_struct(self):
        if not CREATE_STRUCT: return None
        dtm = currentProgram.getDataTypeManager()
        struct = self.find_target_struct(dtm)
        if struct:
            print("[+] Updating: {}".format(struct.getName()))
            struct.deleteAll()
            struct.setPackingEnabled(False)
        else:
            print("[+] Creating: {}".format(self.struct_name))
            struct = StructureDataType(self.struct_name, 0)
            struct.setPackingEnabled(False) 
        
        # FIX: Pre-allocation
        max_needed = 0
        if self.parent_struct: max_needed = self.parent_struct.getLength()
        if self.vtable_offset >= 0: max_needed = max(max_needed, self.vtable_offset + self.ptr_size)
        for off, dt in self.fields.items():
            max_needed = max(max_needed, off + dt.getLength())
        
        if max_needed == 0: max_needed = 4 # Min size
        for _ in range(max_needed): struct.add(Undefined1DataType.dataType)
        
        current_offset = 0
        if self.parent_struct:
            try:
                for i in range(self.parent_struct.getLength()): struct.clearComponent(i)
                struct.replaceAtOffset(0, self.parent_struct, self.parent_struct.getLength(), "base", "Parent")
            except: pass

        if self.vtable_struct and self.vtable_offset >= 0:
             try:
                 for i in range(self.ptr_size): struct.clearComponent(self.vtable_offset + i)
                 struct.replaceAtOffset(self.vtable_offset, self.fields[self.vtable_offset], self.ptr_size, "vtable_{}".format(self.struct_name), "Auto-VTable")
                 self.fields.pop(self.vtable_offset, None)
             except: pass

        for off in sorted(self.fields.keys()):
            dt = self.fields[off]
            
            # Recursion Fix
            if dt.getName() == self.struct_name:
                dt = PointerDataType(struct)
            
            try:
                for i in range(dt.getLength()): struct.clearComponent(off + i)
                struct.replaceAtOffset(off, dt, dt.getLength(), "field_0x{:x}".format(off), "Auto")
            except Exception as e:
                self.log("    [Create] Failed field 0x{:x}: {}".format(off, str(e)), 1)

        if not struct.getDataTypeManager():
            return dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)
        return struct

    def update_function_signature(self, func, struct_dt):
        print("[+] Updating Signature...")
        ptr_type = PointerDataType(struct_dt)
        return_var = func.getReturn()
        call_conv = func.getCallingConventionName()
        params = func.getParameters()
        new_params = ArrayList()
        if len(params) > 0:
            p0 = ParameterImpl("this", ptr_type, currentProgram)
            new_params.add(p0)
            for i in range(1, len(params)): new_params.add(params[i])
        try:
            func.updateFunction(call_conv, return_var, new_params, 
                                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, 
                                True, SourceType.USER_DEFINED)
        except: pass

# -----------------------------------------------------------------------------
# RUNNER
# -----------------------------------------------------------------------------
def run():
    print("---------------------------------------------------")
    print("Auto Class Cascade v47")
    initial_func = currentProgram.getListing().getFunctionContaining(currentLocation.getAddress())
    if not initial_func: return
    queue = [initial_func]
    visited = set()
    while queue:
        func = queue.pop(0)
        if func.getEntryPoint() in visited: continue
        visited.add(func.getEntryPoint())
        recoverer = ClassRecoverer(func)
        new_candidates = recoverer.analyze()
        if new_candidates:
            for c in new_candidates:
                if c.getEntryPoint() not in visited:
                    queue.append(c)
    print("---------------------------------------------------")

run()