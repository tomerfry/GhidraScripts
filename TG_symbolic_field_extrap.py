# Uses Z3 to analyze C++ Constructors, deduce class size/fields, and identify VTables
# @category C++
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.data import StructureDataType, PointerDataType, VoidDataType, IntegerDataType, CharDataType

# -----------------------------------------------------------------------------
# Z3 SETUP
# -----------------------------------------------------------------------------
try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False
    print("[!] Error: z3 module not found. Please install it (pip install z3-solver).")

# -----------------------------------------------------------------------------
# ANALYSIS ENGINE
# -----------------------------------------------------------------------------

class ClassAnalyzer:
    def __init__(self, func):
        self.func = func
        self.solver = z3.Solver()
        self.memory_log = {} # offset -> (size, value_type)
        self.vtable_addr = None
        self.is_constructor = False
        self.class_size = 0
        
        # Initialize 'this' as a symbolic bitvector
        self.ptr_size = currentProgram.getDefaultPointerSize()
        self.this_sym = z3.BitVec('THIS', 64) 
        
        self.vn_map = {} 

    def analyze(self):
        print("Analyzing: {}".format(self.func.getName()))
        
        # Decompile
        decomplib = DecompInterface()
        decomplib.openProgram(currentProgram)
        res = decomplib.decompileFunction(self.func, 30, TaskMonitor.DUMMY)
        if not res.decompileCompleted():
            print("  [!] Decompilation failed.")
            return

        high_func = res.getHighFunction()
        
        # 1. Identify 'this' parameter (Argument 0)
        param0, type_name = self.get_this_param(high_func)
        
        if not param0:
            print("  [!] Could not identify 1st parameter (Function takes void?).")
            return

        if "int" in type_name.lower():
            print("  [!] WARNING: First parameter is type '{}'.".format(type_name))
            print("      This looks like main(argc, ...), not a Class Method.")
            print("      Analysis will likely yield no results.")

        # Map 'this' varnode to our symbolic variable
        self.vn_map[param0] = self.this_sym
        
        # 2. Walk P-Code to track 'this' usage
        # We iterate High P-Code ops
        ops = high_func.getPcodeOps()
        for op in ops:
            self.process_op(op)
            
        # 3. Report Results
        self.report()

    def get_this_param(self, high_func):
        """ Safe way to get the Varnode of the first parameter """
        # Access the Local Symbol Map
        sym_map = high_func.getLocalSymbolMap()
        if sym_map.getNumParams() < 1:
            return None, "void"
            
        # Get the HighSymbol for Param 0
        param_sym = sym_map.getParamSymbol(0)
        if not param_sym:
            return None, "void"
            
        # Get the Data Type name for logging
        dt_name = "unknown"
        if param_sym.getDataType():
            dt_name = param_sym.getDataType().getName()

        # Get the HighVariable -> Varnode
        high_var = param_sym.getHighVariable()
        if high_var:
            return high_var.getRepresentative(), dt_name
            
        return None, dt_name

    def get_sym(self, varnode):
        """ Retrieve Z3 expression for a varnode """
        if not varnode: return None
        
        # Check if mapped
        if varnode in self.vn_map:
            return self.vn_map[varnode]
        
        # Check if constant
        if varnode.isConstant():
            return z3.BitVecVal(varnode.getOffset(), 64)
            
        return None

    def process_op(self, op):
        opcode = op.getOpcode()
        
        # --- POINTER ARITHMETIC ---
        if opcode in [PcodeOp.PTRADD, PcodeOp.INT_ADD]:
            in0 = self.get_sym(op.getInput(0))
            in1 = self.get_sym(op.getInput(1))
            
            if in0 is not None and in1 is not None:
                stride = 1
                if opcode == PcodeOp.PTRADD:
                    idx_stride = op.getInput(2)
                    if idx_stride: stride = idx_stride.getOffset()

                # Symbolic addition
                try:
                    res = in0 + (in1 * stride)
                    self.vn_map[op.getOutput()] = res
                except:
                    pass

        # --- COPY / CAST ---
        elif opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT]:
            in0 = self.get_sym(op.getInput(0))
            if in0 is not None:
                self.vn_map[op.getOutput()] = in0

        # --- STORE (Writing to a field) ---
        elif opcode == PcodeOp.STORE:
            ptr_vn = op.getInput(1)
            val_vn = op.getInput(2)
            
            ptr_sym = self.get_sym(ptr_vn)
            
            if ptr_sym is not None:
                # Check if ptr is "THIS + Offset"
                # Simplify (ptr - THIS)
                try:
                    diff = z3.simplify(ptr_sym - self.this_sym)
                    
                    if z3.is_const(diff): 
                        # We found a write to (THIS + K)
                        offset = diff.as_long()
                        
                        size = 0
                        val_type = "unknown"
                        
                        if val_vn: 
                            size = val_vn.getSize()
                            if val_vn.isConstant():
                                val_type = "const 0x{:x}".format(val_vn.getOffset())
                                # Check for VTable write at offset 0
                                if offset == 0:
                                    self.check_vtable(val_vn.getOffset())
                            else:
                                val_type = "variable"
                                
                        self.memory_log[offset] = (size, val_type)
                        
                        if offset + size > self.class_size:
                            self.class_size = offset + size
                except:
                    pass

    def check_vtable(self, addr_val):
        """ Checks if the constant written to offset 0 is in memory """
        mem = currentProgram.getMemory()
        addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
        if mem.contains(addr):
            self.vtable_addr = addr_val
            self.is_constructor = True

    def report(self):
        print("\n[+] Analysis Results")
        
        if self.is_constructor:
            print("    [!] ROLE: CONSTRUCTOR / DESTRUCTOR")
            print("    [!] VTable detected: 0x{:x}".format(self.vtable_addr))
        else:
            print("    [*] Role: Standard Function (No VTable init detected)")

        if self.class_size > 0:
            print("    [*] Duced Class Size: {} bytes (approx)".format(self.class_size))
        
        if self.memory_log:
            print("    [*] Detected Field Writes (relative to param_1):")
            for off in sorted(self.memory_log.keys()):
                size, vtype = self.memory_log[off]
                print("        +0x{:02x} (size: {}) : {}".format(off, size, vtype))
        else:
            print("    [-] No field writes detected.")
            
        print("    (Note: If this is 'main', no field writes are expected on argc)")

# -----------------------------------------------------------------------------
# RUNNER
# -----------------------------------------------------------------------------

if HAS_Z3:
    print("---------------------------------------------------")
    print("Z3 C++ Class Analyzer v2")
    
    func = currentProgram.getListing().getFunctionContaining(currentLocation.getAddress())
    if func:
        analyzer = ClassAnalyzer(func)
        analyzer.analyze()
    else:
        print("Cursor is not inside a function.")
        
    print("---------------------------------------------------")