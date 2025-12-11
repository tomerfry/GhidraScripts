# Solves branch conditions and correlates variables to their origin (malloc, params, etc.)
# @category Analysis
# @runtime PyGhidra

import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp

# -----------------------------------------------------------------------------
# Z3 SETUP
# -----------------------------------------------------------------------------
try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

# -----------------------------------------------------------------------------
# ORIGIN TRACING (The New Logic)
# -----------------------------------------------------------------------------

def get_function_name_from_call(call_op):
    """
    Resolves the name of the function being called by a CALL PcodeOp.
    """
    # Input 0 of a CALL is the destination address
    addr_vn = call_op.getInput(0)
    if addr_vn and addr_vn.isAddress():
        addr = addr_vn.getAddress()
        func = currentProgram.getListing().getFunctionAt(addr)
        if func:
            return func.getName()
    return "unknown_func"

def trace_origin(varnode, depth=0):
    """
    Recursively traces a Varnode back to its 'source' to generate a descriptive name.
    Handles Casts, Copies, and identifies Calls/Loads.
    """
    if depth > 5: return "complex_chain" # Prevent infinite recursion
    if varnode is None: return "err"

    # 1. Check if it has a specific Decompiler Name (e.g., "iVar1" or "__dest")
    # We prefer the origin description, but keep the name as fallback
    var_name = "var"
    high = varnode.getHigh()
    if high:
        sym = high.getSymbol()
        if sym:
            var_name = sym.getName() # e.g., "__dest" or "param_1"
            # If it's a parameter, stop here
            if sym.isParameter():
                return "param_{}".format(var_name)

    # 2. Check the Defining P-Code Operation
    def_op = varnode.getDef()
    
    # If no definition, it's a raw input/global
    if def_op is None:
        return var_name 

    opcode = def_op.getOpcode()

    # --- CASE A: Function Call Result ---
    if opcode == PcodeOp.CALL:
        func_name = get_function_name_from_call(def_op)
        return "ret_{}".format(func_name)

    # --- CASE B: Indirect Call ---
    elif opcode == PcodeOp.CALLIND:
        return "ret_indirect_call"
        
    # --- CASE C: Memory Load ---
    elif opcode == PcodeOp.LOAD:
        return "mem_val_{}".format(var_name)

    # --- CASE D: Casts and Copies (The Glue) ---
    # If it's just a move/cast, ignore this step and look at the parent
    elif opcode in [PcodeOp.CAST, PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE]:
        return trace_origin(def_op.getInput(0), depth + 1)

    # --- CASE E: Pointer Math (Struct access) ---
    elif opcode in [PcodeOp.PTRADD, PcodeOp.PTRSUB]:
        # Often "param_1 + 0x180"
        base_name = trace_origin(def_op.getInput(0), depth + 1)
        return "{}_field".format(base_name)

    return "{}_from_{}".format(var_name, def_op.getMnemonic())

# -----------------------------------------------------------------------------
# SOLVER LOGIC
# -----------------------------------------------------------------------------

def get_high_pcode_block(addr):
    """ Decompile and find block containing cursor """
    func = currentProgram.getListing().getFunctionContaining(addr)
    if not func: return None, None, "Cursor not in function."

    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    res = decomplib.decompileFunction(func, 30, TaskMonitor.DUMMY)
    if not res.decompileCompleted(): return None, None, "Decompilation failed."

    high_func = res.getHighFunction()
    blocks = high_func.getBasicBlocks()
    for block in blocks:
        if block.contains(addr):
            return high_func, block, None
    return None, None, "Block not found."

def solve_with_z3(cbranch_op):
    # 1. Trace the Condition
    cond_vn = cbranch_op.getInput(1)
    def_op = cond_vn.getDef()
    
    if not def_op: return "Complex condition."

    # 2. Extract Comparison
    in0 = def_op.getInput(0)
    in1 = def_op.getInput(1)
    opcode = def_op.getOpcode()
    mnemonic = def_op.getMnemonic()

    target_val = 0
    var_size = 64
    target_varnode = None

    # Identify which side is the variable and which is constant
    if in1.isConstant():
        target_val = in1.getOffset()
        var_size = in1.getSize() * 8
        target_varnode = in0
    elif in0.isConstant():
        target_val = in0.getOffset()
        var_size = in0.getSize() * 8
        target_varnode = in1
    else:
        return "Complex (Var vs Var). Needs constant side."

    if var_size == 0: var_size = 64
    
    # --- CRITICAL STEP: NAME THE VARIABLE ---
    # Trace the variable back to its source (malloc, param, etc.)
    origin_name = trace_origin(target_varnode)
    print("    -> Traced Origin: '{}'".format(origin_name))
    
    # 3. Z3 Solve
    solver = z3.Solver()
    # We use the Origin Name as the variable name in Z3!
    x = z3.BitVec(origin_name, var_size)
    
    if opcode == PcodeOp.INT_EQUAL:
        solver.add(x == target_val)
        op_sym = "=="
    elif opcode == PcodeOp.INT_NOTEQUAL:
        solver.add(x != target_val)
        op_sym = "!="
    elif opcode == PcodeOp.INT_LESS or opcode == PcodeOp.INT_SLESS:
        solver.add(x < target_val)
        op_sym = "<"
    elif opcode == PcodeOp.INT_LESSEQUAL or opcode == PcodeOp.INT_SLESSEQUAL:
        solver.add(x <= target_val)
        op_sym = "<="
    else:
        return "Opcode {} not supported.".format(mnemonic)

    if solver.check() == z3.sat:
        sol = solver.model()[x].as_long()
        return "Constraint: ({} {} 0x{:X}) \n>>> REQUIRED VALUE: 0x{:X}".format(
            origin_name, op_sym, target_val, sol)
    else:
        return "Unsatisfiable."

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------

def run():
    print("---------------------------------------------------")
    print("Z3 Origin Solver")
    if not HAS_Z3:
        print("[!] Error: 'z3' module missing.")
        return

    # 1. Get Context
    high_func, block, err = get_high_pcode_block(currentLocation.getAddress())
    if err:
        print("[!] " + err)
        return

    # 2. Find Branch (Tail or Predecessor)
    target_op = None
    
    # Check current block tail
    iter = block.getIterator()
    last = None
    for op in iter: last = op
    if last and last.getOpcode() == PcodeOp.CBRANCH:
        target_op = last
    else:
        # Check predecessors
        print("[*] Checking scope predecessors...")
        for i in range(block.getInSize()):
            pred = block.getIn(i)
            iter = pred.getIterator()
            plast = None
            for op in iter: plast = op
            if plast and plast.getOpcode() == PcodeOp.CBRANCH:
                target_op = plast
                break
    
    if target_op:
        print("[*] Found Branch: {}".format(target_op.getSeqnum().getTarget()))
        try:
            res = solve_with_z3(target_op)
            print("\n" + res)
        except Exception as e:
            print("[!] Analysis Error: " + str(e))
    else:
        print("[!] No controlling 'if' found.")
    print("---------------------------------------------------")

run()