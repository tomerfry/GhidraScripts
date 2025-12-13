# Extracts branch constraints and loop patterns for security assessment
# @category Analysis
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.pcode import PcodeOp

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

# -----------------------------------------------------------------------------
# ORIGIN TRACING
# -----------------------------------------------------------------------------

def get_function_name_from_call(call_op):
    addr_vn = call_op.getInput(0)
    if addr_vn and addr_vn.isAddress():
        addr = addr_vn.getAddress()
        func = currentProgram.getListing().getFunctionAt(addr)
        if func:
            return func.getName()
    return "unknown"

def get_high_symbol_name(varnode):
    if varnode is None:
        return None
    high = varnode.getHigh()
    if high:
        sym = high.getSymbol()
        if sym:
            name = sym.getName()
            if name and name not in ["UNNAMED", ""] and not name.startswith("Var"):
                return name
        name = high.getName()
        if name and name not in ["UNNAMED", ""] and not name.startswith("Var"):
            return name
    return None

def is_param(varnode):
    if varnode is None:
        return False
    high = varnode.getHigh()
    if high:
        sym = high.getSymbol()
        return sym and sym.isParameter()
    return False

def trace_origin(varnode, depth=0):
    if depth > 10 or varnode is None:
        return "complex"

    sym_name = get_high_symbol_name(varnode)
    
    high = varnode.getHigh()
    if high:
        sym = high.getSymbol()
        if sym and sym.isParameter():
            return sym.getName()
    
    def_op = varnode.getDef()
    
    if def_op is None:
        if varnode.isConstant():
            return "0x{:X}".format(varnode.getOffset())
        return sym_name if sym_name else "input"

    opcode = def_op.getOpcode()

    if opcode == PcodeOp.CALL:
        return "ret_{}".format(get_function_name_from_call(def_op))
    elif opcode == PcodeOp.CALLIND:
        return "ret_indirect"
    elif opcode == PcodeOp.LOAD:
        addr_vn = def_op.getInput(1)
        addr_expr = trace_ptr_expr(addr_vn, depth + 1)
        if "[" in addr_expr or "->" in addr_expr:
            return addr_expr
        return "*({})".format(addr_expr)
    elif opcode in [PcodeOp.CAST, PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE]:
        return trace_origin(def_op.getInput(0), depth + 1)
    elif opcode == PcodeOp.PTRADD:
        base = trace_origin(def_op.getInput(0), depth + 1)
        index = trace_origin(def_op.getInput(1), depth + 1)
        if index == "0x0":
            return base
        return "{}[{}]".format(base, index)
    elif opcode == PcodeOp.PTRSUB:
        base = trace_origin(def_op.getInput(0), depth + 1)
        offset_vn = def_op.getInput(1)
        if offset_vn.isConstant():
            return "{}.off_{:X}".format(base, offset_vn.getOffset())
        return "{}.field".format(base)
    elif opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT]:
        left = trace_origin(def_op.getInput(0), depth + 1)
        right = trace_origin(def_op.getInput(1), depth + 1)
        op_map = {PcodeOp.INT_ADD: "+", PcodeOp.INT_SUB: "-", PcodeOp.INT_MULT: "*"}
        return "({} {} {})".format(left, op_map.get(opcode, "?"), right)
    elif opcode == PcodeOp.MULTIEQUAL:
        return sym_name if sym_name else "loop_var"

    return sym_name if sym_name else "expr"

def trace_ptr_expr(varnode, depth=0):
    if depth > 10 or varnode is None:
        return "ptr"
    
    sym_name = get_high_symbol_name(varnode)
    
    high = varnode.getHigh()
    if high:
        sym = high.getSymbol()
        if sym and sym.isParameter():
            return sym.getName()
    
    def_op = varnode.getDef()
    if def_op is None:
        return sym_name if sym_name else "ptr"
    
    opcode = def_op.getOpcode()
    
    if opcode in [PcodeOp.CAST, PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT]:
        return trace_ptr_expr(def_op.getInput(0), depth + 1)
    elif opcode == PcodeOp.PTRADD:
        base = trace_ptr_expr(def_op.getInput(0), depth + 1)
        index_vn = def_op.getInput(1)
        if index_vn.isConstant():
            idx = index_vn.getOffset()
            if idx == 0:
                return base
            return "{}[0x{:X}]".format(base, idx)
        return "{}[{}]".format(base, trace_origin(index_vn, depth + 1))
    elif opcode == PcodeOp.PTRSUB:
        base = trace_ptr_expr(def_op.getInput(0), depth + 1)
        offset_vn = def_op.getInput(1)
        if offset_vn.isConstant():
            return "{}->off_{:X}".format(base, offset_vn.getOffset())
        return "{}->field".format(base)
    elif opcode == PcodeOp.INT_ADD:
        left = trace_ptr_expr(def_op.getInput(0), depth + 1)
        right_vn = def_op.getInput(1)
        if right_vn.isConstant():
            return "({}+0x{:X})".format(left, right_vn.getOffset())
        return "{}[{}]".format(left, trace_origin(right_vn, depth + 1))
    
    return sym_name if sym_name else "ptr"

# -----------------------------------------------------------------------------
# LOOP ANALYSIS (Enhanced for Security)
# -----------------------------------------------------------------------------

def resolve_context(varnode):
    """Get descriptive string for varnode with context."""
    if not varnode:
        return "?"
    
    if varnode.isConstant():
        return "0x{:X}".format(varnode.getOffset())
    
    name = "var"
    high = varnode.getHigh()
    if high:
        sym = high.getSymbol()
        if sym:
            name = sym.getName()
            if sym.isParameter():
                return "param:{}".format(name)
    
    # Peek through copies/casts
    def_op = varnode.getDef()
    if def_op:
        opcode = def_op.getOpcode()
        if opcode in [PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT]:
            input0 = def_op.getInput(0)
            if input0.isConstant():
                return "0x{:X}".format(input0.getOffset())
            h2 = input0.getHigh()
            if h2 and h2.getSymbol() and h2.getSymbol().isParameter():
                return "param:{}".format(h2.getSymbol().getName())
        elif opcode == PcodeOp.CALL:
            return "ret_{}".format(get_function_name_from_call(def_op))
    
    if name and name not in ["UNNAMED", ""] and not name.startswith("Var"):
        return name
    return "var"

def detect_loop_cycle(phi_op):
    """Check if MULTIEQUAL is loop induction variable. Returns (init_vn, back_vn) or None."""
    inputs = [phi_op.getInput(i) for i in range(phi_op.getNumInputs())]
    phi_out = phi_op.getOutput()
    
    back_edge = None
    init_val = None
    
    for vn in inputs:
        is_cycle = False
        def_op = vn.getDef()
        
        if def_op:
            # Check 2 levels deep for cycle
            for k in range(def_op.getNumInputs()):
                inp = def_op.getInput(k)
                if inp == phi_out:
                    is_cycle = True
                    break
                inp_def = inp.getDef()
                if inp_def:
                    for m in range(inp_def.getNumInputs()):
                        if inp_def.getInput(m) == phi_out:
                            is_cycle = True
                            break
        
        if is_cycle:
            back_edge = vn
        else:
            init_val = vn
    
    return (init_val, back_edge) if back_edge else None

def analyze_loop_step(phi_output, back_edge):
    """Determine how loop variable changes each iteration."""
    def_op = back_edge.getDef()
    if not def_op:
        return "?", "unknown"
    
    opcode = def_op.getOpcode()
    
    # INDIRECT means memory load - not a real induction variable
    if opcode == PcodeOp.INDIRECT:
        return "indirect", "indirect"
    
    # Find step value
    step_val = "?"
    for i in range(def_op.getNumInputs()):
        vn = def_op.getInput(i)
        if vn != phi_output:
            step_val = resolve_context(vn)
            break
    
    op_map = {
        PcodeOp.INT_ADD: ("+=", "inc"),
        PcodeOp.INT_SUB: ("-=", "dec"),
        PcodeOp.INT_MULT: ("*=", "mult"),
        PcodeOp.PTRADD: ("ptr+=", "ptr"),
        PcodeOp.COPY: ("copy", "copy"),
    }
    
    if opcode in op_map:
        sym, kind = op_map[opcode]
        return "{} {}".format(sym, step_val), kind
    
    return "op:{}".format(def_op.getMnemonic()), "complex"

def find_loop_bound(phi_op, all_constraints=None):
    """Find exit condition by searching successors and matching constraints."""
    block = phi_op.getParent()
    var_name = resolve_context(phi_op.getOutput())
    
    result = {
        "expr": "unknown",
        "op": "?",
        "bound_val": None,
        "bound_source": None,
        "user_controlled": False,
        "off_by_one": False,
    }
    
    # Strategy 1: Match constraints that involve the loop var
    if all_constraints:
        best_constraint = None
        best_score = -1
        
        for c in all_constraints:
            expr = c.get("expr", "")
            score = 0
            
            # Check if constraint involves our loop variable
            # Handle cases like "__size" matching "(__size + 0x1)"
            var_base = var_name.replace("param:", "")
            if var_base in expr:
                score += 5
            
            # Score by operator type
            if "!=" in expr:
                score += 3
            elif "<" in expr and "<=" not in expr:
                score += 4
            elif "<=" in expr:
                score += 3
            elif "==" in expr:
                score += 1  # Likely break, not bound
            
            # Boost for large constant values (likely max bound)
            val = c.get("val")
            if val is not None and val > 1:
                score += 2
            if val is not None and val >= 0x80:
                score += 3
            
            if score > best_score:
                best_score = score
                best_constraint = c
        
        if best_constraint and best_score >= 5:
            c = best_constraint
            result["expr"] = c["expr"]
            if "!=" in c["expr"]:
                result["op"] = "!="
            elif "<=" in c["expr"]:
                result["op"] = "<="
                result["off_by_one"] = True
            elif "<" in c["expr"]:
                result["op"] = "<"
            
            if c.get("val") is not None:
                result["bound_val"] = c["val"]
                result["bound_source"] = "const"
            if c.get("user_input"):
                result["user_controlled"] = True
                result["bound_source"] = "param"
            return result
    
    # Strategy 2: Search successor blocks for CBRANCHs
    blocks_to_check = [block]
    for i in range(block.getOutSize()):
        out_blk = block.getOut(i)
        if out_blk:
            blocks_to_check.append(out_blk)
    
    branches = []
    for blk in blocks_to_check:
        if blk is None:
            continue
        it = blk.getIterator()
        for op in it:
            if op.getOpcode() == PcodeOp.CBRANCH:
                branches.append(op)
    
    if not branches:
        return result
    
    best_branch = None
    best_score = -1
    
    for br in branches:
        cond_vn = br.getInput(1)
        def_op = cond_vn.getDef()
        if not def_op:
            continue
        
        opcode = def_op.getOpcode()
        in0 = def_op.getInput(0)
        in1 = def_op.getInput(1)
        
        score = 0
        if opcode == PcodeOp.INT_NOTEQUAL:
            score = 3
        elif opcode in [PcodeOp.INT_LESS, PcodeOp.INT_SLESS]:
            score = 4
        elif opcode in [PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL]:
            score = 3
        elif opcode == PcodeOp.INT_EQUAL:
            score = 1
        
        const_val = None
        if in1.isConstant():
            const_val = in1.getOffset()
        elif in0.isConstant():
            const_val = in0.getOffset()
        
        if const_val is not None and const_val > 1:
            score += 3
        if const_val is not None and const_val >= 0x100:
            score += 2
        
        if score > best_score:
            best_score = score
            best_branch = br
    
    if not best_branch:
        return result
    
    cond_vn = best_branch.getInput(1)
    def_op = cond_vn.getDef()
    if not def_op:
        return result
    
    opcode = def_op.getOpcode()
    in0 = def_op.getInput(0)
    in1 = def_op.getInput(1)
    
    v0 = resolve_context(in0)
    v1 = resolve_context(in1)
    
    op_syms = {
        PcodeOp.INT_LESS: "<",
        PcodeOp.INT_SLESS: "<s",
        PcodeOp.INT_LESSEQUAL: "<=",
        PcodeOp.INT_SLESSEQUAL: "<=s",
        PcodeOp.INT_EQUAL: "==",
        PcodeOp.INT_NOTEQUAL: "!=",
    }
    
    sym = op_syms.get(opcode, "?")
    result["expr"] = "{} {} {}".format(v0, sym, v1)
    result["op"] = sym
    
    if "<=" in sym:
        result["off_by_one"] = True
    
    if in1.isConstant():
        result["bound_val"] = in1.getOffset()
        result["bound_source"] = "const"
    elif in0.isConstant():
        result["bound_val"] = in0.getOffset()
        result["bound_source"] = "const"
    else:
        for vn in [in0, in1]:
            if is_param(vn):
                result["user_controlled"] = True
                result["bound_source"] = "param"
                break
    
    return result

def detect_loop_mem_ops(high_func, loop_block):
    """Detect memory operations in loop for buffer overflow analysis."""
    mem_ops = []
    block_addr = loop_block.getStart()
    
    # Simple heuristic: check blocks reachable from loop header
    for op in high_func.getPcodeOps():
        opcode = op.getOpcode()
        if opcode == PcodeOp.STORE:
            addr_vn = op.getInput(1)
            mem_ops.append(("WRITE", trace_origin(addr_vn)))
        elif opcode == PcodeOp.CALL:
            fname = get_function_name_from_call(op)
            if any(d in fname.lower() for d in ["cpy", "mov", "set", "cat"]):
                mem_ops.append(("CALL", fname))
    
    return mem_ops[:5]  # Limit output

def compute_max_iterations(bound_info, init_val, step_str):
    """Use Z3 to compute max iterations if possible."""
    if not HAS_Z3:
        return bound_info.get("bound_val")
    
    bound_val = bound_info.get("bound_val")
    if bound_val is None:
        return None
    
    # Parse init value
    init = 0
    if isinstance(init_val, str):
        if init_val.startswith("0x"):
            try:
                init = int(init_val, 16)
            except:
                return bound_val
        elif init_val.isdigit():
            init = int(init_val)
    
    # Parse step
    step = 1
    if "+=" in step_str:
        parts = step_str.split("+=")
        if len(parts) > 1:
            s = parts[1].strip()
            if s.startswith("0x"):
                try:
                    step = int(s, 16)
                except:
                    step = 1
            elif s.isdigit():
                step = int(s)
    
    if step == 0:
        return None  # Infinite loop
    
    op = bound_info.get("op", "")
    
    # Calculate iterations
    if op in ["<", "<s"]:
        if bound_val > init:
            return (bound_val - init + step - 1) // step
    elif op in ["<=", "<=s"]:
        if bound_val >= init:
            return (bound_val - init + step) // step
    elif op == "!=":
        if bound_val > init:
            return (bound_val - init + step - 1) // step
    
    return bound_val


def collect_loops(high_func, all_constraints=None):
    """Collect all loops with security-relevant info."""
    loops = []
    loops_by_block = {}
    
    for op in high_func.getPcodeOps():
        if op.getOpcode() == PcodeOp.MULTIEQUAL:
            result = detect_loop_cycle(op)
            if result:
                init_vn, back_vn = result
                block_id = op.getParent().getStart().getOffset()
                if block_id not in loops_by_block:
                    loops_by_block[block_id] = []
                loops_by_block[block_id].append((op, init_vn, back_vn))
    
    for block_id in sorted(loops_by_block.keys()):
        vars_in_loop = loops_by_block[block_id]
        bound_info = find_loop_bound(vars_in_loop[0][0], all_constraints)
        
        loop_vars = []
        flags = []
        
        for (phi, init_vn, back_vn) in vars_in_loop:
            var_name = resolve_context(phi.getOutput())
            init_val = resolve_context(init_vn) if init_vn else "?"
            step_str, step_kind = analyze_loop_step(phi.getOutput(), back_vn)
            
            # Skip INDIRECT and COPY vars - they're noise
            if step_kind in ["indirect", "copy"]:
                continue
            
            init_from_param = init_vn and "param:" in resolve_context(init_vn)
            
            loop_vars.append({
                "name": var_name,
                "init": init_val,
                "step": step_str,
                "kind": step_kind,
                "param_init": init_from_param,
            })
            
            if init_from_param:
                flags.append("PARAM_INIT({})".format(var_name))
        
        # Security flags
        if bound_info["user_controlled"]:
            flags.append("USER_CONTROLLED_BOUND")
        if bound_info["off_by_one"]:
            flags.append("OFF_BY_ONE_RISK")
        if bound_info["bound_source"] == "variable":
            flags.append("VARIABLE_BOUND")
        if bound_info["bound_val"] and bound_info["bound_val"] > 0x10000:
            flags.append("LARGE_BOUND(0x{:X})".format(bound_info["bound_val"]))
        if bound_info["op"] == "!=":
            flags.append("EQUALITY_EXIT")  # Can miss exit condition
        
        # Calculate actual max iterations
        if loop_vars:
            first_var = loop_vars[0]
            max_iters = compute_max_iterations(bound_info, first_var["init"], first_var["step"])
            if max_iters is not None:
                bound_info["max_iters"] = max_iters
        
        loops.append({
            "addr": block_id,
            "bound": bound_info,
            "vars": loop_vars,
            "flags": list(set(flags)),
        })
    
    return loops

# -----------------------------------------------------------------------------
# CONSTRAINT EXTRACTION
# -----------------------------------------------------------------------------

COMPARE_OPS = {
    PcodeOp.INT_EQUAL: ("==", lambda x, v: x == v),
    PcodeOp.INT_NOTEQUAL: ("!=", lambda x, v: x != v),
    PcodeOp.INT_LESS: ("<", lambda x, v: z3.ULT(x, v)),
    PcodeOp.INT_SLESS: ("<s", lambda x, v: x < v),
    PcodeOp.INT_LESSEQUAL: ("<=", lambda x, v: z3.ULE(x, v)),
    PcodeOp.INT_SLESSEQUAL: ("<=s", lambda x, v: x <= v),
}

def extract_constraint(cbranch_op):
    cond_vn = cbranch_op.getInput(1)
    def_op = cond_vn.getDef()
    
    if not def_op:
        return None

    opcode = def_op.getOpcode()
    if opcode not in COMPARE_OPS:
        if opcode == PcodeOp.BOOL_NEGATE:
            inner = def_op.getInput(0).getDef()
            if inner and inner.getOpcode() in COMPARE_OPS:
                def_op = inner
                opcode = def_op.getOpcode()
            else:
                return None
        else:
            return None

    in0 = def_op.getInput(0)
    in1 = def_op.getInput(1)
    
    if in1.isConstant():
        var_vn, const_val = in0, in1.getOffset()
        var_size = in1.getSize() * 8
    elif in0.isConstant():
        var_vn, const_val = in1, in0.getOffset()
        var_size = in0.getSize() * 8
    else:
        left = trace_origin(in0)
        right = trace_origin(in1)
        sym = COMPARE_OPS[opcode][0]
        return {
            "expr": "{} {} {}".format(left, sym, right),
            "line": str(cbranch_op.getSeqnum().getTarget()),
            "type": "var_vs_var",
            "user_input": is_param(in0) or is_param(in1),
        }

    if var_size == 0:
        var_size = 64

    origin = trace_origin(var_vn)
    sym, z3_op = COMPARE_OPS[opcode]
    
    user_input = is_param(var_vn)
    
    return {
        "var": origin,
        "op": sym,
        "val": const_val,
        "line": str(cbranch_op.getSeqnum().getTarget()),
        "expr": "{} {} 0x{:X}".format(origin, sym, const_val),
        "user_input": user_input,
    }

def collect_constraints(high_func):
    constraints = []
    seen = set()

    for block in high_func.getBasicBlocks():
        it = block.getIterator()
        for op in it:
            if op.getOpcode() == PcodeOp.CBRANCH:
                try:
                    c = extract_constraint(op)
                    if c and c["expr"] not in seen:
                        seen.add(c["expr"])
                        constraints.append(c)
                except:
                    pass

    return constraints

# -----------------------------------------------------------------------------
# DANGEROUS CALL DETECTION
# -----------------------------------------------------------------------------

DANGEROUS_FUNCS = {
    "strcpy": "BUFFER_OVERFLOW",
    "strcat": "BUFFER_OVERFLOW", 
    "sprintf": "BUFFER_OVERFLOW",
    "gets": "BUFFER_OVERFLOW",
    "memcpy": "BUFFER_OVERFLOW",
    "memmove": "BUFFER_OVERFLOW",
    "scanf": "BUFFER_OVERFLOW",
    "printf": "FORMAT_STRING",
    "fprintf": "FORMAT_STRING",
    "syslog": "FORMAT_STRING",
    "free": "USE_AFTER_FREE/DOUBLE_FREE",
    "malloc": "ALLOCATION",
    "calloc": "ALLOCATION",
    "realloc": "ALLOCATION",
}

def collect_dangerous_calls(high_func):
    calls = []
    for op in high_func.getPcodeOps():
        if op.getOpcode() == PcodeOp.CALL:
            func_name = get_function_name_from_call(op)
            # Check both exact and partial matches
            for pattern, risk in DANGEROUS_FUNCS.items():
                if pattern in func_name.lower():
                    args = []
                    for i in range(1, op.getNumInputs()):
                        args.append(trace_origin(op.getInput(i)))
                    calls.append({
                        "func": func_name,
                        "risk": risk,
                        "args": args,
                        "line": str(op.getSeqnum().getTarget()),
                    })
                    break
    return calls

# -----------------------------------------------------------------------------
# COMMENT GENERATION
# -----------------------------------------------------------------------------

def format_security_comment(func, constraints, loops, dangerous_calls):
    lines = []
    lines.append("=" * 55)
    lines.append("SECURITY ANALYSIS: {}".format(func.getName()))
    lines.append("=" * 55)
    
    # Dangerous calls
    if dangerous_calls:
        lines.append("")
        lines.append("DANGEROUS CALLS:")
        for c in dangerous_calls:
            lines.append("  [{:<12}] {}({}) @ {}".format(
                c["risk"][:12], c["func"], ", ".join(c["args"][:3]), c["line"]))
    
    # Loops with security analysis
    if loops:
        lines.append("")
        lines.append("LOOPS ({} detected):".format(len(loops)))
        for i, loop in enumerate(loops, 1):
            lines.append("")
            lines.append("  LOOP #{} @ 0x{:X}".format(i, loop["addr"]))
            lines.append("    Condition: {}".format(loop["bound"]["expr"]))
            
            max_iters = loop["bound"].get("max_iters")
            bound_val = loop["bound"].get("bound_val")
            if max_iters is not None:
                lines.append("    Max iters: {} (bound=0x{:X})".format(max_iters, bound_val or 0))
            elif bound_val is not None:
                lines.append("    Bound: 0x{:X}".format(bound_val))
            elif loop["bound"].get("bound_source"):
                lines.append("    Bound from: {}".format(loop["bound"]["bound_source"]))
            
            for v in loop["vars"]:
                lines.append("    Var: {} | init={} | step={}".format(
                    v["name"], v["init"], v["step"]))
            
            if loop["flags"]:
                for flag in loop["flags"]:
                    lines.append("    [!] {}".format(flag))
    
    # Branch constraints
    if constraints:
        lines.append("")
        lines.append("BRANCH CONSTRAINTS ({} total):".format(len(constraints)))
        for c in constraints:
            marker = "[USER] " if c.get("user_input") else "       "
            lines.append("  {}{} @ {}".format(marker, c["expr"], c["line"]))
    
    # Risk summary
    risks = []
    if dangerous_calls:
        risks.append("{} dangerous call(s)".format(len(dangerous_calls)))
    user_bounds = sum(1 for l in loops if "USER_CONTROLLED_BOUND" in l.get("flags", []))
    if user_bounds:
        risks.append("{} user-controlled loop(s)".format(user_bounds))
    obo = sum(1 for l in loops if "OFF_BY_ONE_RISK" in l.get("flags", []))
    if obo:
        risks.append("{} off-by-one risk(s)".format(obo))
    user_constraints = sum(1 for c in constraints if c.get("user_input"))
    if user_constraints:
        risks.append("{} user-controlled branch(es)".format(user_constraints))
    
    if risks:
        lines.append("")
        lines.append("RISK SUMMARY: {}".format("; ".join(risks)))
    
    lines.append("=" * 55)
    return "\n".join(lines)

def set_inline_comments(func, constraints, loops, dangerous_calls):
    """Add comments at relevant code locations."""
    listing = currentProgram.getListing()
    
    # Add comments at dangerous calls
    for c in dangerous_calls:
        try:
            addr = toAddr(c["line"])
            code_unit = listing.getCodeUnitAt(addr)
            if code_unit:
                comment = "[{}] {}({})".format(c["risk"], c["func"], ", ".join(c["args"][:2]))
                existing = code_unit.getComment(code_unit.EOL_COMMENT) or ""
                if comment not in existing:
                    code_unit.setComment(code_unit.EOL_COMMENT, comment)
        except:
            pass
    
    # Add comments at loop headers
    for i, loop in enumerate(loops, 1):
        try:
            addr = toAddr(loop["addr"])
            code_unit = listing.getCodeUnitAt(addr)
            if code_unit:
                lines = ["LOOP #{}".format(i)]
                lines.append("  Cond: {}".format(loop["bound"]["expr"]))
                max_iters = loop["bound"].get("max_iters") or loop["bound"].get("bound_val")
                if max_iters:
                    lines.append("  Max: {}".format(max_iters))
                # Only show actual induction vars (not INDIRECT noise)
                for v in loop["vars"]:
                    if v["kind"] in ["inc", "dec", "ptr"]:
                        lines.append("  {} [{}] {}".format(v["name"], v["init"], v["step"]))
                if loop["flags"]:
                    lines.append("  [!] {}".format(", ".join(loop["flags"])))
                
                comment = "\n".join(lines)
                code_unit.setComment(code_unit.PRE_COMMENT, comment)
        except:
            pass
    
    # Add comments at security-relevant constraints
    for c in constraints:
        if not c.get("user_input"):
            continue
        try:
            addr = toAddr(c["line"])
            code_unit = listing.getCodeUnitAt(addr)
            if code_unit:
                comment = "[USER INPUT] {}".format(c["expr"])
                existing = code_unit.getComment(code_unit.EOL_COMMENT) or ""
                if comment not in existing:
                    new_comment = (existing + " | " + comment) if existing else comment
                    code_unit.setComment(code_unit.EOL_COMMENT, new_comment)
        except:
            pass

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------

def run():
    print("=" * 60)
    print("Security Constraint Harvester")
    print("=" * 60)
    
    if not HAS_Z3:
        print("[!] Z3 not installed (optional)")

    func = currentProgram.getListing().getFunctionContaining(currentLocation.getAddress())
    if not func:
        print("[!] Place cursor inside a function")
        return

    print("[*] Analyzing: {} @ {}".format(func.getName(), func.getEntryPoint()))
    
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    res = decomplib.decompileFunction(func, 30, TaskMonitor.DUMMY)
    
    if not res.decompileCompleted():
        print("[!] Decompilation failed")
        return

    high_func = res.getHighFunction()
    
    # Collect constraints first (needed for loop bound detection)
    constraints = collect_constraints(high_func)
    loops = collect_loops(high_func, constraints)
    dangerous_calls = collect_dangerous_calls(high_func)
    
    print("[+] {} constraints, {} loops, {} dangerous calls".format(
        len(constraints), len(loops), len(dangerous_calls)))
    
    # Add inline comments at relevant locations
    set_inline_comments(func, constraints, loops, dangerous_calls)
    
    # Print summary to console
    print("\n[DANGEROUS CALLS]")
    for c in dangerous_calls:
        print("  {} @ {} - {}".format(c["func"], c["line"], c["risk"]))
    
    print("\n[LOOPS]")
    for i, loop in enumerate(loops, 1):
        print("  Loop #{} @ 0x{:X}: {}".format(i, loop["addr"], loop["bound"]["expr"]))
        if loop["flags"]:
            print("    Flags: {}".format(", ".join(loop["flags"])))
    
    print("\n[+] Inline comments added to function")

run()