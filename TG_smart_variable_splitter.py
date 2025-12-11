# Intelligent Variable Splitter v3 (Iterator-Aware)
# Renames variables only if safe; Detects iterators to prevent bad renames.
# @category Analysis
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.plugin.core.colorizer import ColorizingService
from java.awt import Color

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------
APPLY_RENAMES = True        # Rename safe candidates?
ADD_COMMENTS = True         # Annotate split points?
ADD_BOOKMARKS = True        # Add bookmarks?
HIGHLIGHT_SPLITS = True     # Highlight split points in Orange?

# -----------------------------------------------------------------------------
# ANALYSIS ENGINE
# -----------------------------------------------------------------------------

def get_return_value_constant(func):
    """ Checks if a function returns a hardcoded constant. """
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    res = decomplib.decompileFunction(func, 30, TaskMonitor.DUMMY)
    if not res.decompileCompleted(): return None
    
    hf = res.getHighFunction()
    found_val = None
    first = True
    
    for op in hf.getPcodeOps():
        if op.getOpcode() == PcodeOp.RETURN:
            if op.getNumInputs() > 1:
                ret_vn = op.getInput(1)
                if ret_vn.isConstant():
                    val = ret_vn.getOffset()
                    if first:
                        found_val = val
                        first = False
                    elif found_val != val:
                        return None
                else:
                    return None
    return found_val

def trace_concrete_origin(varnode, depth=0):
    if depth > 3: return None, None
    if not varnode: return None, None
    if varnode.isConstant(): return varnode.getOffset(), "Constant"

    def_op = varnode.getDef()
    if not def_op: return None, None

    opcode = def_op.getOpcode()
    if opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT]:
        return trace_concrete_origin(def_op.getInput(0), depth+1)

    if opcode == PcodeOp.CALL:
        addr = def_op.getInput(0).getAddress()
        func = currentProgram.getListing().getFunctionAt(addr)
        if func:
            val = get_return_value_constant(func)
            if val is not None:
                return val, "Return from {}".format(func.getName())

    return None, None

def is_iterator(high_var):
    """
    Scans ALL usages of a variable to see if it is ever incremented/decremented/modified.
    Returns True if the variable is 'Dynamic' (math applied to it).
    """
    # Scan all Pcode ops in the function to see where this variable is used
    # Note: HighVariable.getInstances() gives us the varnodes
    instances = high_var.getInstances()
    
    for vn in instances:
        # Check if this varnode is an INPUT to a math operation
        descendants = vn.getDescendants()
        for op in descendants:
            opcode = op.getOpcode()
            # If used in ADD, SUB, PTRADD, or MULTIEQUAL (Phi loop)
            # It is likely an iterator/state variable, not a static constant holder.
            if opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.PTRADD, PcodeOp.MULTIEQUAL]:
                return True
    return False

def highlight_instruction(addr):
    """ Highlights the instruction at addr in Orange """
    if not HIGHLIGHT_SPLITS: return
    listing = currentProgram.getListing()
    cu = listing.getCodeUnitAt(addr)
    if cu:
        tool = state.getTool()
        service = tool.getService(ColorizingService)
        if service:
            service.setBackgroundColor(cu.getMinAddress(), cu.getMaxAddress(), Color(255, 200, 100)) # Orange

def process_assignments(high_func):
    assignments = {}
    ops = high_func.getPcodeOps()
    for op in ops:
        output = op.getOutput()
        if output:
            high = output.getHigh()
            if high:
                if high not in assignments: assignments[high] = []
                assignments[high].append(output)

    trans_id = currentProgram.startTransaction("Smart Splitter")
    
    try:
        for high_var, instances in assignments.items():
            sym = high_var.getSymbol()
            if not sym or sym.isParameter() or sym.isGlobal(): continue
            
            var_name = sym.getName()
            sorted_instances = sorted(instances, key=lambda v: v.getPCAddress())
            
            # --- ITERATOR CHECK ---
            # If this variable is involved in math (looping), we must be VERY careful renaming it.
            is_iter = is_iterator(high_var)
            if is_iter:
                # print("  [Info] {} is an Iterator/Dynamic. Renaming restricted.".format(var_name))
                pass

            for i in range(1, len(sorted_instances)):
                current_vn = sorted_instances[i]
                addr = current_vn.getPCAddress()
                
                # Check for Concrete Assignment
                conc_val, source = trace_concrete_origin(current_vn)
                
                if conc_val is not None:
                    msg = "Variable '{}' becomes Concrete: 0x{:x} ({})".format(var_name, conc_val, source)
                    print("[*] Match at {}: {}".format(addr, msg))
                    
                    if ADD_COMMENTS:
                        currentProgram.getListing().setComment(addr, CodeUnit.PRE_COMMENT, "[Split] " + msg)
                    
                    if ADD_BOOKMARKS:
                        currentProgram.getBookmarkManager().setBookmark(addr, "Analysis", "Split Candidate", msg)
                        
                    if HIGHLIGHT_SPLITS:
                        highlight_instruction(addr)

                    # DECISION: Do we rename?
                    if is_iter:
                        print("    [!] Skipping Rename: Variable is an Iterator/Loop Counter.")
                        print("        Renaming would confuse the loop logic (e.g., 'is_0 = is_0 + 1').")
                    elif APPLY_RENAMES:
                        # It's not an iterator, just a reused temp slot. Safe to rename.
                        new_name = "{}_is_0x{:x}".format(var_name, conc_val)
                        try:
                            sym.setName(new_name, SourceType.USER_DEFINED)
                            print("    [+] Renamed to: " + new_name)
                        except: pass
                
                else:
                    # Symbolic reassignment (Function return, etc)
                    # Only flag if not an iterator update
                    pass 

    finally:
        currentProgram.endTransaction(trans_id, True)

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------

def run():
    print("---------------------------------------------------")
    print("Smart Variable Splitter v3")
    
    func = currentProgram.getListing().getFunctionContaining(currentLocation.getAddress())
    if not func: return

    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    res = decomplib.decompileFunction(func, 30, TaskMonitor.DUMMY)
    if not res.decompileCompleted(): return
    
    process_assignments(res.getHighFunction())
    print("---------------------------------------------------")

run()