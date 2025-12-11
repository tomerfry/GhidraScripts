# Deep Data-Flow Tracer (Interprocedural: Drills Down into Callees & Climbs Up to Callers)
# @category Analysis
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import RefType

# -----------------------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------------------
MAX_DEPTH = 3           # How many functions deep to trace
TRACE_CALLERS = True    # Set to False if you don't want to scan "parents" (can be slow)

# -----------------------------------------------------------------------------
# HELPER CLASS
# -----------------------------------------------------------------------------

class OriginTracer:
    def __init__(self):
        self.decomplib = DecompInterface()
        self.decomplib.openProgram(currentProgram)
        self.monitor = TaskMonitor.DUMMY

    def decompile(self, func):
        """ Helper to decompile a function and get high PCode """
        res = self.decomplib.decompileFunction(func, 30, self.monitor)
        if res.decompileCompleted():
            return res.getHighFunction()
        return None

    def get_caller_info(self, func, param_index):
        """
        Finds the first function that calls 'func' and retrieves the value 
        passed to the parameter at 'param_index'.
        """
        # Get references to the function entry point
        entry = func.getEntryPoint()
        refs = currentProgram.getReferenceManager().getReferencesTo(entry)
        
        for ref in refs:
            if ref.getReferenceType().isCall():
                caller_addr = ref.getFromAddress()
                caller_func = currentProgram.getListing().getFunctionContaining(caller_addr)
                
                if caller_func:
                    # Decompile the caller
                    hf = self.decompile(caller_func)
                    if not hf: continue
                    
                    # Find the specific CALL op at that address
                    # Note: Pcode addresses map roughly to assembly, but we iterate to be safe
                    ops = hf.getPcodeOps(caller_addr)
                    while ops.hasNext():
                        op = ops.next()
                        if op.getOpcode() == PcodeOp.CALL:
                            # Verify call target
                            call_target = op.getInput(0).getAddress()
                            if call_target == entry:
                                # Get the input passed to the specific arg index
                                # Input 0 = Address, Input 1 = Arg 0, Input 2 = Arg 1...
                                input_idx = param_index + 1
                                if input_idx < op.getNumInputs():
                                    return caller_func, op.getInput(input_idx)
        return None, None

    def get_return_val_source(self, func):
        """
        Decompiles 'func' and finds the source of the RETURN value.
        """
        hf = self.decompile(func)
        if not hf: return None
        
        ops = hf.getPcodeOps()
        for op in ops:
            if op.getOpcode() == PcodeOp.RETURN:
                # RETURN takes inputs: (Input 0=Indirect Ref?), Input 1 = The Value
                # Usually Input 1 is the return register (EAX/RAX)
                if op.getNumInputs() > 1:
                    return hf, op.getInput(1)
        return None

    def trace(self, varnode, func_context, depth=0):
        """
        Recursive tracing function.
        """
        indent = "    " * depth
        prefix = "-> " if depth > 0 else ""
        
        if depth > MAX_DEPTH:
            print("{} [Limit Reached]".format(indent))
            return

        if not varnode:
            print("{} {} [Error] Null Varnode".format(indent, prefix))
            return

        # 1. CONSTANT
        if varnode.isConstant():
            print("{} {} [ORIGIN] CONSTANT: 0x{:X}".format(indent, prefix, varnode.getOffset()))
            return

        # 2. DEFINITION
        def_op = varnode.getDef()
        
        # If no definition, it's a Param or Global
        if not def_op:
            if varnode.isAddress():
                print("{} {} [ORIGIN] GLOBAL MEMORY: {}".format(indent, prefix, varnode.getAddress()))
                return
            
            # Check if it's a Parameter (HighVariable check)
            high = varnode.getHigh()
            if high and high.getSymbol() and high.getSymbol().isParameter():
                param_idx = high.getSymbol().getCategoryIndex()
                print("{} {} [Scope] PARAMETER #{} of '{}'".format(indent, prefix, param_idx, func_context.getName()))
                
                if TRACE_CALLERS:
                    print("{}     [Action] Climbing UP to caller...".format(indent))
                    caller_func, passed_val = self.get_caller_info(func_context, param_idx)
                    
                    if caller_func:
                        print("{}     [Caller] Found call in '{}'".format(indent, caller_func.getName()))
                        self.trace(passed_val, caller_func, depth + 1)
                    else:
                        print("{}     [?] No callers found or analysis failed.".format(indent))
                return
                
            print("{} {} [?] Unknown Source (Input Var)".format(indent, prefix))
            return

        opcode = def_op.getOpcode()
        
        # 3. CALL (Return Value) -> DRILL DOWN
        if opcode == PcodeOp.CALL:
            # Input 0 is the function address
            call_addr = def_op.getInput(0).getAddress()
            callee = currentProgram.getListing().getFunctionAt(call_addr)
            
            if callee:
                callee_name = callee.getName()
                if callee.isExternal():
                    print("{} {} [ORIGIN] EXTERNAL API: {}".format(indent, prefix, callee_name))
                else:
                    print("{} {} [Scope] RETURN VALUE from '{}'".format(indent, prefix, callee_name))
                    print("{}     [Action] Drilling DOWN into callee...".format(indent))
                    
                    # Open the callee
                    callee_hf, ret_src = self.get_return_val_source(callee)
                    if ret_src:
                        self.trace(ret_src, callee, depth + 1)
                    else:
                        print("{}     [?] Could not resolve return value in callee.".format(indent))
            else:
                print("{} {} [ORIGIN] INDIRECT CALL / UNKNOWN".format(indent, prefix))
        
        # 4. COPY / CAST / EXTENSIONS -> Continue Trace
        elif opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE]:
            self.trace(def_op.getInput(0), func_context, depth)
            
        # 5. POINTER ARITHMETIC -> Trace Base
        elif opcode in [PcodeOp.PTRSUB, PcodeOp.PTRADD, PcodeOp.INT_ADD]:
            # Usually Input 0 is the base
            # print("{} {} [Op] Math/Ptr Calc ({})".format(indent, prefix, def_op.getMnemonic()))
            self.trace(def_op.getInput(0), func_context, depth)
            
        # 6. LOAD -> Memory Read
        elif opcode == PcodeOp.LOAD:
            ptr = def_op.getInput(1) # Input 0 is Space ID, Input 1 is Address
            print("{} {} [ORIGIN] MEMORY LOAD from ptr".format(indent, prefix))
            # Optional: You could trace the pointer 'ptr' here to see WHERE we are reading from
            # self.trace(ptr, func_context, depth + 1)
            
        else:
            print("{} {} [Stop] Terminated by Op: {}".format(indent, prefix, def_op.getMnemonic()))

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------

def run():
    print("---------------------------------------------------")
    print("Interprocedural Data-Flow Tracer")
    print("---------------------------------------------------")
    
    tracer = OriginTracer()
    
    # 1. Get Context
    addr = currentLocation.getAddress()
    func = currentProgram.getListing().getFunctionContaining(addr)
    if not func:
        print("Cursor not in a function.")
        return

    # 2. Get High PCode
    high_func = tracer.decompile(func)
    if not high_func:
        print("Decompilation failed.")
        return
        
    # 3. Find Varnode at Cursor
    # Try to grab the exact token from the Decompiler
    target_vn = None
    try:
        # Check Decompiler Selection
        if "Decompiler" in str(type(currentLocation)):
            token = currentLocation.getToken()
            if token and token.getVarnode():
                target_vn = token.getVarnode()
            elif token and token.getPcodeOp():
                # If they clicked an Op (like call), try to get the output
                target_vn = token.getPcodeOp().getOutput()
    except:
        pass
        
    # Fallback to current address op
    if not target_vn:
        # Just grab the last op at this address
        ops = high_func.getPcodeOps(addr)
        while ops.hasNext():
            op = ops.next()
            if op.getOutput():
                target_vn = op.getOutput() # Take the last one writing a var

    if target_vn:
        print("Tracing Variable: {} (in {})".format(target_vn, func.getName()))
        print("")
        tracer.trace(target_vn, func)
    else:
        print("No variable selected. Please click on a variable in the Decompiler.")

    print("---------------------------------------------------")

run()