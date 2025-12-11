# Detects stack strings (With "Boring String" Filter)
# @category Analysis
# @runtime PyGhidra

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.data import ArrayDataType, CharDataType
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import SourceType

def get_endianness():
    return currentProgram.getLanguage().isBigEndian()

def is_printable(byte_val):
    # ASCII printable
    return (0x20 <= byte_val <= 0x7E) or byte_val == 0x00

def int_to_bytes(value, size, is_big_endian):
    bytes_list = []
    for i in range(size):
        byte = (value >> (i * 8)) & 0xFF
        bytes_list.append(byte)
    if is_big_endian: return list(reversed(bytes_list))
    return bytes_list 

def scan_stack_assignments(high_func):
    stack_memory = {}
    is_be = get_endianness()
    op_iter = high_func.getPcodeOps()
    
    for op in op_iter:
        if op.getOpcode() in [PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT]:
            dest_vn = op.getOutput()
            if not dest_vn: continue
            
            offset = None
            high = dest_vn.getHigh()
            if high:
                sym = high.getSymbol()
                if sym:
                    storage = sym.getStorage()
                    if storage.isStackStorage():
                        offset = storage.getStackOffset()
            
            if offset is None and dest_vn.isAddress() and dest_vn.getAddress().isStackAddress():
                offset = dest_vn.getAddress().getOffset()
                
            if offset is None: continue

            src_vn = op.getInput(0)
            if src_vn and src_vn.isConstant():
                val = src_vn.getOffset()
                size = src_vn.getSize()
                bytes_data = int_to_bytes(val, size, is_be)
                for i in range(len(bytes_data)):
                    stack_memory[offset + i] = bytes_data[i]
    return stack_memory

def clear_stack_range(frame, start_offset, length):
    end_offset = start_offset + length
    vars_to_clear = set()
    for off in range(start_offset, end_offset):
        v = frame.getVariableContaining(off)
        if v: vars_to_clear.add(v.getStackOffset())     
    for v_off in vars_to_clear:
        frame.clearVariable(v_off)

def apply_stack_string(func, start_offset, byte_list):
    # --- FILTER: Ignore "Boring" Strings (Just Nulls) ---
    non_nulls = [b for b in byte_list if b != 0x00]
    
    # If it's pure nulls (zero init), ignore it.
    if len(non_nulls) == 0:
        return 
        
    # If it's mostly nulls and very short, it's likely an integer (e.g., 0x00000041)
    if len(non_nulls) == 1 and len(byte_list) > 2:
        return

    length = len(byte_list)
    clean_chars = []
    for b in byte_list:
        if 0x20 <= b <= 0x7E: clean_chars.append(chr(b))
    string_val = "".join(clean_chars)
    if not string_val: string_val = "str"
    
    print("[*] DETECTED: \"{}\" (Len: {}) at Offset {}".format(string_val, length, start_offset))
    
    char_type = CharDataType.dataType
    array_type = ArrayDataType(char_type, length, 1)
    frame = func.getStackFrame()
    
    try:
        clear_stack_range(frame, start_offset, length)
        var_name = "s_{}_{:x}".format(string_val[:8], abs(start_offset))
        frame.createVariable(
            var_name,
            start_offset,
            array_type,
            SourceType.USER_DEFINED
        )
        print("    -> Applied Type: char[{}] name: {}".format(length, var_name))
        
    except Exception as e:
        print("    [!] Failed to apply: " + str(e))

def run():
    print("---------------------------------------------------")
    print("Stack String Reconstructor v5 (Smart Filter)")
    
    func = currentProgram.getListing().getFunctionContaining(currentLocation.getAddress())
    if not func: return

    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    res = decomplib.decompileFunction(func, 30, TaskMonitor.DUMMY)
    if not res.decompileCompleted(): return
    
    stack_map = scan_stack_assignments(res.getHighFunction())
    if not stack_map:
        print("No constant stack assignments found.")
        return

    sorted_offsets = sorted(stack_map.keys())
    current_seq = []
    start_offset = None
    MIN_LEN = 3 
    
    for i, offset in enumerate(sorted_offsets):
        byte = stack_map[offset]
        
        is_contiguous = False
        if start_offset is not None:
             prev_offset = sorted_offsets[i-1]
             if offset == prev_offset + 1: is_contiguous = True
        
        if is_printable(byte):
            if not is_contiguous:
                if len(current_seq) >= MIN_LEN:
                    apply_stack_string(func, start_offset, current_seq)
                current_seq = [byte]
                start_offset = offset
            else:
                current_seq.append(byte)
        else:
            if len(current_seq) >= MIN_LEN:
                apply_stack_string(func, start_offset, current_seq)
            current_seq = []
            start_offset = None

    if len(current_seq) >= MIN_LEN:
        apply_stack_string(func, start_offset, current_seq)

    print("---------------------------------------------------")

run()