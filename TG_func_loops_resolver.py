# Summarizes all loops in the function and resolves their variables
# @category Analysis
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp

# -----------------------------------------------------------------------------
# HELPER: Name Resolver with Context
# -----------------------------------------------------------------------------
def resolve_context(varnode):
    """
    Returns a string describing the variable.
    If it's a variable, tries to peek back 1 level to see if it's a param or const.
    """
    if not varnode: return "???"
    
    # 1. Direct Constant
    if varnode.isConstant():
        return "0x{:X}".format(varnode.getOffset())
    
    # 2. High Variable Name
    name = "var"
    high = varnode.getHigh()
    if high:
        sym = high.getSymbol()
        if sym:
            name = sym.getName()
            if sym.isParameter():
                return "Param '{}'".format(name)
    
    # 3. Peek Back (Context Resolution)
    # If 'n' is actually just a copy of 'param_1', say that.
    def_op = varnode.getDef()
    if def_op:
        opcode = def_op.getOpcode()
        if opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT]:
            input0 = def_op.getInput(0)
            if input0.isConstant():
                return "Const 0x{:X}".format(input0.getOffset())
            
            # Check if input is param
            h2 = input0.getHigh()
            if h2 and h2.getSymbol() and h2.getSymbol().isParameter():
                return "Param '{}'".format(h2.getSymbol().getName())

    return name

# -----------------------------------------------------------------------------
# LOGIC: Loop Analysis
# -----------------------------------------------------------------------------

def detect_cycle(phi_op):
    """
    Determines if a MULTIEQUAL op is part of a loop (Induction Variable).
    Returns (Init_Varnode, Back_Edge_Varnode) or None.
    """
    inputs = [phi_op.getInput(i) for i in range(phi_op.getNumInputs())]
    
    back_edge_vn = None
    init_vn = None
    
    # Check each input to see if it depends on the Phi Op (Cycle)
    for vn in inputs:
        is_cycle = False
        def_op = vn.getDef()
        
        # Trace back up to 3 levels to find a cycle
        if def_op:
            # Level 1
            for k in range(def_op.getNumInputs()):
                if def_op.getInput(k) == phi_op.getOutput():
                    is_cycle = True
                    break
            
            # Level 2 (e.g. i = i + 1)
            if not is_cycle:
                for k in range(def_op.getNumInputs()):
                    op2 = def_op.getInput(k).getDef()
                    if op2:
                        for m in range(op2.getNumInputs()):
                            if op2.getInput(m) == phi_op.getOutput():
                                is_cycle = True
                                break
        
        if is_cycle:
            back_edge_vn = vn
        else:
            # If it's not the cycle, it's likely the initialization
            init_vn = vn
            
    if back_edge_vn:
        return init_vn, back_edge_vn
    return None

def analyze_step(phi_output, back_edge_input):
    """ Determines how the variable changes (i++ vs i+=4) """
    def_op = back_edge_input.getDef()
    if not def_op: return "Complex Update"

    opcode = def_op.getOpcode()
    
    # Find the factor (the input that ISN'T the loop var)
    factor = "Unknown"
    for i in range(def_op.getNumInputs()):
        vn = def_op.getInput(i)
        if vn != phi_output:
            # Resolve this factor (is it 1? 4? a variable?)
            factor = resolve_context(vn)

    if opcode == PcodeOp.INT_ADD:
        return "+= {}".format(factor)
    elif opcode == PcodeOp.INT_SUB:
        return "-= {}".format(factor)
    elif opcode == PcodeOp.INT_MULT:
        return "*= {}".format(factor)
    elif opcode == PcodeOp.PTRADD:
        stride = 1
        if def_op.getNumInputs() > 2:
            stride = def_op.getInput(2).getOffset()
        return "PtrStride({})".format(stride)
        
    return "Op:{}".format(def_op.getMnemonic())

def find_constraint(phi_op):
    """ Finds the exit condition (Branch) for the loop header """
    block = phi_op.getParent()
    iter = block.getIterator()
    last_op = None
    for op in iter: last_op = op
    
    if last_op and last_op.getOpcode() == PcodeOp.CBRANCH:
        cond_vn = last_op.getInput(1)
        def_op = cond_vn.getDef()
        if def_op:
            # e.g. INT_LESS(i, argc)
            op_str = def_op.getMnemonic().replace("INT_", "")
            
            in0 = def_op.getInput(0)
            in1 = def_op.getInput(1)
            
            # Check which input is our loop var to format nicely
            # We want to format as: (i < 10)
            val0 = resolve_context(in0)
            val1 = resolve_context(in1)
            
            return "while ({} {} {})".format(val0, op_str, val1)
            
    return "Infinite / Complex Exit"

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------

def run():
    print("---------------------------------------------------")
    print("Function Loop Summary")
    
    func = currentProgram.getListing().getFunctionContaining(currentLocation.getAddress())
    if not func:
        print("Cursor not in a function.")
        return

    print("Target: {}\n".format(func.getName()))

    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    res = decomplib.decompileFunction(func, 30, TaskMonitor.DUMMY)
    if not res.decompileCompleted(): return
    high_func = res.getHighFunction()
    
    # 1. Gather all MULTIEQUAL (Phi) ops
    ops = high_func.getPcodeOps()
    loop_vars = []
    
    for op in ops:
        if op.getOpcode() == PcodeOp.MULTIEQUAL:
            # Check if it's a loop variable
            result = detect_cycle(op)
            if result:
                init_vn, back_vn = result
                loop_vars.append((op, init_vn, back_vn))

    if not loop_vars:
        print("[*] No loop induction variables detected.")
        print("    (The function might use 'goto' spaghetti or purely iterator-based structures).")
        return

    # 2. Group by Block (Loops often have multiple vars: i, ptr, state)
    loops_by_block = {}
    for (phi, init, back) in loop_vars:
        block_id = phi.getParent().getStart().getOffset()
        if block_id not in loops_by_block:
            loops_by_block[block_id] = []
        loops_by_block[block_id].append((phi, init, back))

    # 3. Print Report
    loop_count = 1
    for block_id in sorted(loops_by_block.keys()):
        vars_in_loop = loops_by_block[block_id]
        
        # Determine Constraint (Shared by the block)
        # We just grab the constraint from the first var's block
        constraint = find_constraint(vars_in_loop[0][0])
        
        print("LOOP #{} (Header: 0x{:X})".format(loop_count, block_id))
        print("  Condition: {}".format(constraint))
        print("  Variables:")
        
        for (phi, init, back) in vars_in_loop:
            var_name = resolve_context(phi.getOutput())
            start_val = resolve_context(init)
            step_str  = analyze_step(phi.getOutput(), back)
            
            print("    - {} : Start[{}]  Step[{}]".format(
                var_name.ljust(10), 
                start_val, 
                step_str
            ))
        print("")
        loop_count += 1

    print("---------------------------------------------------")

run()