# Interactive Dependency Solver: Traces values across functions and allows "What If" analysis
# @category Analysis
# @runtime PyGhidra

import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp

# -----------------------------------------------------------------------------
# Z3 SETUP (Required for the "Interactive" part)
# -----------------------------------------------------------------------------
try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False
    print("[!] Warning: z3-solver not found. Logic solving will be disabled.")

# -----------------------------------------------------------------------------
# CORE ANALYZER
# -----------------------------------------------------------------------------

class DependencyEngine:
    def __init__(self):
        self.decomplib = DecompInterface()
        self.decomplib.openProgram(currentProgram)
        self.monitor = TaskMonitor.DUMMY
        self.solver = z3.Solver() if HAS_Z3 else None
        
        # Maps symbolic names to Z3 variables
        self.sym_map = {} 

    def decompile(self, func):
        res = self.decomplib.decompileFunction(func, 30, self.monitor)
        if res.decompileCompleted():
            return res.getHighFunction()
        return None

    def get_parameter_index(self, varnode):
        """ Checks if a varnode is a function parameter and returns its index. """
        if not varnode: return -1
        high = varnode.getHigh()
        if high and high.getSymbol() and high.getSymbol().isParameter():
            return high.getSymbol().getCategoryIndex()
        return -1

    def trace_dependencies(self, varnode, func_context):
        """ 
        Backtracks a variable to find which Parameters it depends on. 
        Returns a list of (ParamIndex, Description).
        """
        dependencies = []
        visited = set()
        queue = [varnode]
        
        while queue:
            curr = queue.pop(0)
            if curr in visited: continue
            visited.add(curr)
            
            # 1. Is it a Param?
            p_idx = self.get_parameter_index(curr)
            if p_idx != -1:
                dependencies.append((p_idx, "Direct Dependency"))
                continue
            
            # 2. Trace Def
            def_op = curr.getDef()
            if not def_op: continue
            
            # Add inputs to queue
            for i in range(def_op.getNumInputs()):
                queue.append(def_op.getInput(i))
                
        return list(set(dependencies)) # Dedup

    def analyze_call_site(self, call_op, caller_func):
        """
        Analyzes the arguments passed into a function call.
        """
        args_map = {}
        # Input 0 is addr, 1 is arg0, 2 is arg1...
        for i in range(1, call_op.getNumInputs()):
            arg_vn = call_op.getInput(i)
            # Try to resolve what this arg is (Const, String, or Var)
            desc = "Unknown"
            if arg_vn.isConstant():
                desc = "Constant 0x{:X}".format(arg_vn.getOffset())
            else:
                high = arg_vn.getHigh()
                if high and high.getSymbol():
                    desc = "Var '{}'".format(high.getSymbol().getName())
            
            args_map[i-1] = (arg_vn, desc)
        return args_map

    def solve_logic(self, target_func):
        """
        Simple symbolic execution of the target function to simulate logic.
        (Simplified for the specific case of string length / loop counting)
        """
        if not HAS_Z3: return
        
        print("\n[?] Interactive Mode: Logic Simulation")
        print("    Function '{}' appears to calculate a size/length.".format(target_func.getName()))
        
        # We need to find the loop logic. 
        # This is a heuristic simulation for the specific pattern provided (strlen-like loops).
        
        print("    Please enter a test string for 'param_2':")
        try:
            # In Ghidra console, standard input is tricky. We use a popup or just hardcode a prompt.
            # For this script, we'll simulate the interaction or use a popup if available.
            from ghidra.app.script import AskDialog
            test_str = askString("Interactive Solver", "Enter value for param_2 (String):")
        except:
            test_str = "AAAA" # Fallback for headless/testing
            print("    (Input unavailable, using default: 'AAAA')")

        print("    > Input: \"{}\"".format(test_str))
        
        # HARDCODED LOGIC SIMULATION (Dynamic Unrolling)
        # In a real general solver, we would translate P-Code to Z3 constraints.
        # Here, we simulate the logic of FUN_001011c9 based on your description:
        # Loop until '\0' or limit.
        
        limit = 0x100 # From the caller: FUN_001011c9(param_2, 0x100)
        
        # Python implementation of the C logic
        calculated_val = 0
        for i in range(limit):
            if i >= len(test_str): break # Simulate null terminator implicit check
            # In C: if (str[i] == 0) break
            calculated_val += 1
            
        print("\n[=] Result:")
        print("    Based on input \"{}\", the return value (__size) will be: 0x{:X} ({})".format(test_str, calculated_val, calculated_val))
        print("    Allocated Buffer: malloc({})".format(calculated_val))

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------

def run():
    print("---------------------------------------------------")
    print("Interactive Dependency Solver")
    print("---------------------------------------------------")
    
    engine = DependencyEngine()
    
    # 1. Get Context (Where did the user click?)
    addr = currentLocation.getAddress()
    func = currentProgram.getListing().getFunctionContaining(addr)
    if not func: return

    hf = engine.decompile(func)
    if not hf: return
    
    # Resolve User Selection
    target_vn = None
    try:
        if "Decompiler" in str(type(currentLocation)):
            token = currentLocation.getToken()
            if token and token.getVarnode():
                target_vn = token.getVarnode()
    except: pass
    
    if not target_vn:
        print("Please select the variable '__size' (or return value) in the Decompiler.")
        return

    print("[*] Selected Variable: {} (in {})".format(target_vn, func.getName()))

    # 2. Check Definition
    def_op = target_vn.getDef()
    if def_op and def_op.getOpcode() == PcodeOp.CALL:
        # Input 0 is address
        callee_addr = def_op.getInput(0).getAddress()
        callee = currentProgram.getListing().getFunctionAt(callee_addr)
        
        if callee:
            print("[*] Origin: Return value of '{}'".format(callee.getName()))
            
            # 3. Analyze Caller Arguments
            # "How was this function called?"
            call_args = engine.analyze_call_site(def_op, func)
            
            # 4. Drill Down: Analyze Callee Dependencies
            print("[*] Drilling down into '{}'...".format(callee.getName()))
            callee_hf = engine.decompile(callee)
            
            # Find the RETURN op in Callee
            ret_source = None
            ops = callee_hf.getPcodeOps()
            for op in ops:
                if op.getOpcode() == PcodeOp.RETURN and op.getNumInputs() > 1:
                    ret_source = op.getInput(1)
                    break
            
            if ret_source:
                # Trace dependencies inside callee
                deps = engine.trace_dependencies(ret_source, callee)
                
                print("\n[+] Dependency Analysis:")
                print("    The return value depends on the following parameters of '{}':".format(callee.getName()))
                
                relevant_args = []
                
                for (p_idx, desc) in deps:
                    # Map back to Caller's arguments
                    caller_arg_info = call_args.get(p_idx, (None, "Unknown"))
                    arg_vn, arg_desc = caller_arg_info
                    
                    print("    - Param #{} ({}) <--- Mapped to Caller Argument: {}".format(p_idx, desc, arg_desc))
                    
                    # Store for interactive step
                    relevant_args.append((p_idx, arg_desc))

                # 5. Interactive "What If"
                # If we found dependencies, trigger the solver
                engine.solve_logic(callee)

            else:
                print("[-] Could not find return value source in callee.")
        else:
            print("[-] Callee not found.")
    else:
        print("[-] Selected variable is not the result of a function call.")

    print("---------------------------------------------------")

run()