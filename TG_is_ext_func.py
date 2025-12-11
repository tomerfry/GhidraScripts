# Check if function is Internal/External and drill down through Thunks
# @category Analysis

from ghidra.app.decompiler import DecompilerLocation, ClangFuncNameToken
from ghidra.program.util import OperandFieldLocation
from ghidra.program.model.listing import Function

def get_function_from_selection():
    """ Resolves the function object from the cursor location. """
    target_func = None
    token_name = "None"

    # 1. Handle Decompiler View
    if isinstance(currentLocation, DecompilerLocation):
        token = currentLocation.getToken()
        if token: token_name = token.getText()
            
        if isinstance(token, ClangFuncNameToken):
            pcode = token.getPcodeOp()
            if pcode:
                # Function Call
                op_input = pcode.getInput(0)
                if op_input and op_input.isAddress():
                    target_func = getFunctionAt(op_input.getAddress())
            if not target_func:
                # Function Definition
                res = currentLocation.getDecompile()
                if res: target_func = res.getFunction()      
        else:
            print("(!) Selection '{}' is not a function.".format(token_name))
            return None

    # 2. Handle Listing View
    elif isinstance(currentLocation, OperandFieldLocation):
        instruction = currentProgram.getListing().getInstructionAt(currentLocation.getAddress())
        if instruction:
            op_index = currentLocation.getOperandIndex()
            refs = instruction.getOperandReferences(op_index)
            for ref in refs:
                func = getFunctionAt(ref.getToAddress())
                if func:
                    target_func = func
                    break
    
    return target_func

def get_library_name(func):
    """ Helper to safely get the library name of an external function. """
    try:
        ext_loc = func.getExternalLocation()
        if ext_loc:
            parent_name = ext_loc.getLibraryName()
            if parent_name:
                return parent_name
    except:
        pass
    return "Unknown Library"

def analyze_function(func, depth=0):
    """
    Analyzes function type and drills down if it is a Thunk.
    """
    indent = "    " * depth
    prefix = ">>" if depth > 0 else "Selected Function"
    
    print("{} {}: {}".format(indent, prefix, func.getName()))
    
    is_external = func.isExternal()
    is_thunk = func.isThunk()
    
    if is_external:
        lib_name = get_library_name(func)
        print("{} [!] STATUS: EXTERNAL IMPORT".format(indent))
        print("{}     Source: {}".format(indent, lib_name))
        print("{}     Note:   Not implemented in this binary.".format(indent))
        
    elif is_thunk:
        print("{} [~] STATUS: THUNK (Trampoline)".format(indent))
        print("{}     Note:   Proxy code inside this binary.".format(indent))
        print("{}     Action: Drilling down to destination...".format(indent))
        
        # DRILL DOWN LOGIC
        # True = recursive (find the final destination)
        thunked_func = func.getThunkedFunction(True) 
        
        if thunked_func:
            print("")
            analyze_function(thunked_func, depth + 1)
        else:
            print("{}     [?] Error: Could not resolve thunk destination.".format(indent))
            
    else:
        print("{} [*] STATUS: INTERNAL IMPLEMENTATION".format(indent))
        print("{}     Addr:   {}".format(indent, func.getEntryPoint()))
        print("{}     Note:   Code logic exists physically in this binary.".format(indent))

# --- Main Execution ---
print("---------------------------------------------------")
target = get_function_from_selection()

if target:
    analyze_function(target)
else:
    print("Analysis failed: Please select a function name.")
print("---------------------------------------------------")
