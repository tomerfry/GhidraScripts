# Create a structure from a sequence of function pointers at the current selection.
# Works with any function pointer table, not just vtables.
# Supports redefining existing structures.
# @category Structure
# @keybinding ctrl shift p
# @menupath
# @toolbar
# @runtime PyGhidra

from ghidra.app.script import GhidraScript
from ghidra.program.model.data import (
    StructureDataType, PointerDataType, FunctionDefinitionDataType,
    DataTypeConflictHandler, CategoryPath, Undefined, VoidDataType,
    ArrayDataType
)
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import Variable
from ghidra.util.exception import CancelledException
from ghidra.app.decompiler.util import FillOutStructureCmd
from ghidra.program.util import ProgramLocation
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler.component import DecompilerUtils

def run():
    dtm = currentProgram.getDataTypeManager()
    pointer_size = currentProgram.getDefaultPointerSize()
    af = currentProgram.getAddressFactory()
    
    # Check if we have a selection or just a cursor position
    selection = currentSelection
    start_addr = None
    end_addr = None
    use_selection = False
    redefinition_mode = False
    existing_struct_data = None
    
    if selection is not None and not selection.isEmpty():
        # Use the selection range
        use_selection = True
        start_addr = selection.getMinAddress()
        end_addr = selection.getMaxAddress()
        
        # Check if the selection contains an existing function pointer table structure
        existing_data = getDataAt(start_addr)
        if (existing_data is not None and 
            existing_data.getDataType() is not None and
            existing_data.getDataType().getName().endswith("_struct") and
            hasattr(existing_data.getDataType(), 'getNumComponents')):
            
            existing_struct_data = existing_data
            redefinition_mode = True
            
            # Calculate the actual end address based on the structure size
            struct_size = existing_struct_data.getDataType().getLength()
            end_addr = start_addr.add(struct_size - 1)
            
            println("Found existing function pointer table structure: {}".format(
                existing_struct_data.getDataType().getName()))
            println("Structure has {} components, size {} bytes".format(
                existing_struct_data.getDataType().getNumComponents(), struct_size))
            
            if not askYesNo("Redefine Structure", 
                           "Redefine existing structure '{}' with current function information?".format(
                               existing_struct_data.getDataType().getName())):
                println("Operation cancelled by user.")
                return
        else:
            # Regular selection range processing
            # Calculate expected number of entries based on selection size
            selection_size = end_addr.subtract(start_addr) + 1
            expected_entries = selection_size // pointer_size
            
            println("Using selection range: {} to {}".format(start_addr, end_addr))
            println("Selection size: {} bytes, expected {} pointer entries".format(selection_size, expected_entries))
            
            if expected_entries == 0:
                printerr("Selection is too small to contain function pointers.")
                return
                
            if selection_size % pointer_size != 0:
                println("Warning: Selection size ({}) is not aligned to pointer size ({})".format(
                    selection_size, pointer_size))
                if not askYesNo("Continue Anyway?", "Selection is not pointer-aligned. Continue?"):
                    return
    else:
        # No selection - use cursor position and ask for method
        if currentAddress is None:
            printerr("No address selected. Please select an address or make a selection range.")
            return
            
        start_addr = currentAddress
        
        # Ask user how they want to determine the range
        range_method = askChoice("Range Selection", 
                               "How should the table range be determined?",
                               ["Auto-detect (scan until invalid)", "Manual entry count"],
                               "Auto-detect (scan until invalid)")
        
        if range_method == "Manual entry count":
            # Ask for maximum number of entries to scan
            max_entries_str = askString("Max Entries", "Number of entries to process:", "32")
            try:
                max_entries = int(max_entries_str) if max_entries_str else 32
                end_addr = start_addr.add((max_entries * pointer_size) - 1)
                expected_entries = max_entries
                use_selection = True  # Treat as fixed range
                println("Using manual range: {} entries from {} to {}".format(max_entries, start_addr, end_addr))
            except ValueError:
                printerr("Invalid number entered.")
                return
        else:
            # Auto-detect mode - will scan until invalid entries
            use_selection = False
            expected_entries = 0  # Unknown
            println("Using auto-detect mode starting from: {}".format(start_addr))

    # Handle namespace and structure name based on mode
    target_namespace = None
    struct_name = None
    
    if redefinition_mode:
        # Extract information from existing structure
        existing_struct_type = existing_struct_data.getDataType()
        struct_name = existing_struct_type.getName()
        
        # Try to extract namespace from structure category path
        category_path = existing_struct_type.getCategoryPath()
        if category_path.toString().startswith("/FunctionPtrTables/"):
            path_parts = category_path.toString().split("/")
            if len(path_parts) >= 3 and path_parts[2]:  # /FunctionPtrTables/NamespaceName/
                namespace_name = path_parts[2]
                try:
                    symbol_table = currentProgram.getSymbolTable()
                    global_namespace = currentProgram.getGlobalNamespace()
                    target_namespace = symbol_table.getNamespace(namespace_name, global_namespace)
                    if target_namespace is not None:
                        println("Using existing namespace from structure: {}".format(namespace_name))
                    else:
                        println("Namespace '{}' from structure not found, will recreate".format(namespace_name))
                        target_namespace = symbol_table.getOrCreateNameSpace(global_namespace, namespace_name, SourceType.USER_DEFINED)
                except Exception as e:
                    println("Could not restore namespace '{}': {}".format(namespace_name, str(e)))
        
        println("Redefining structure: {} (namespace: {})".format(
            struct_name, target_namespace.getName() if target_namespace else "Global"))
        
        # Calculate number of entries from existing structure
        expected_entries = existing_struct_type.getNumComponents()
        
    else:
        # Check if there's a symbol at start address for auto-namespace detection
        symbol_at_addr = getSymbolAt(start_addr)
        auto_namespace_available = (symbol_at_addr is not None and 
                                   symbol_at_addr.getParentNamespace() is not None and 
                                   not symbol_at_addr.getParentNamespace().isGlobal())
        
        # Ask about namespace handling
        namespace_mode = "manual"  # default
        
        if auto_namespace_available:
            parent_ns = symbol_at_addr.getParentNamespace()
            use_auto_namespace = askYesNo("Use Symbol Namespace", 
                                        "Found symbol '{}' in namespace '{}'. Use this namespace?".format(
                                            symbol_at_addr.getName(), 
                                            parent_ns.getName()))
            if use_auto_namespace:
                namespace_mode = "auto"
                target_namespace = parent_ns
                println("Using auto-detected namespace: {}".format(target_namespace.getName()))
        
        if namespace_mode == "manual":
            namespace_name = askString("Namespace", 
                                     "Enter namespace for the table and functions (leave empty for global):", 
                                     "")
            if namespace_name and len(namespace_name.strip()) > 0:
                # Create or get the namespace
                try:
                    symbol_table = currentProgram.getSymbolTable()
                    # Get the global namespace first
                    global_namespace = currentProgram.getGlobalNamespace()
                    target_namespace = symbol_table.getOrCreateNameSpace(global_namespace, namespace_name.strip(), SourceType.USER_DEFINED)
                    println("Using namespace: {}".format(target_namespace.getName()))
                except Exception as e:
                    printerr("Failed to create namespace '{}': {}".format(namespace_name, e))
                    target_namespace = None
        
        # Get user input for structure name and processing options
        default_struct_name = "FunctionPtrTable"
        if target_namespace is not None and not target_namespace.isGlobal():
            default_struct_name = target_namespace.getName() + "_struct"
        elif symbol_at_addr is not None:
            default_struct_name = symbol_at_addr.getName() + "_struct"
        
        struct_name = askString("Structure Name", "Enter name for the function pointer table structure:", default_struct_name)
        if struct_name is None:
            println("Script cancelled by user.")
            return

    # Ask for maximum number of entries to scan (only for auto-detect mode)
    max_consecutive_nulls = 3  # Stop after 3 consecutive null/invalid entries
    if not use_selection and not redefinition_mode:
        null_limit_str = askString("Null Limit", "Stop after how many consecutive null/invalid entries?", "3")
        try:
            max_consecutive_nulls = int(null_limit_str) if null_limit_str else 3
        except ValueError:
            max_consecutive_nulls = 3

    # Ask if we should auto-detect calling convention (skip for redefinition mode)
    auto_calling_conv = True  # default for redefinition
    calling_convention = "__stdcall"  # default
    
    if not redefinition_mode:
        auto_calling_conv = askYesNo("Auto-detect Calling Convention", 
                                    "Should the script attempt to set appropriate calling conventions?")
    
    # Get calling convention if auto-detect is disabled or determine it automatically
    if auto_calling_conv:
        # Try to determine appropriate calling convention based on program architecture
        arch = currentProgram.getLanguage().getProcessor().toString().lower()
        if "x86" in arch and currentProgram.getDefaultPointerSize() == 4:
            calling_convention = "__thiscall"  # Common for C++ member functions on x86
        elif "x86" in arch:
            calling_convention = "__fastcall"
    elif not redefinition_mode:
        calling_convention = askString("Calling Convention", 
                                     "Enter calling convention (__stdcall, __cdecl, __thiscall, __fastcall):", 
                                     "__stdcall")
        if calling_convention is None:
            calling_convention = "__stdcall"

    # Set up category - use namespace-aware category if available
    if target_namespace is not None and not target_namespace.isGlobal():
        category_path = CategoryPath("/FunctionPtrTables/{}".format(target_namespace.getName()))
    else:
        category_path = CategoryPath("/FunctionPtrTables")
        
    if dtm.getCategory(category_path) is None:
        try:
            dtm.createCategory(category_path)
            println("Created category: {}".format(category_path))
        except Exception as e:
            printerr("Failed to create category {}: {}".format(category_path, e))
            category_path = CategoryPath.ROOT
            println("Using root category instead.")

    # Check for existing structure (skip confirmation for redefinition mode)
    existing_struct = dtm.getDataType(category_path, struct_name)
    if existing_struct is not None and not redefinition_mode:
        if not askYesNo("Overwrite Existing Structure?", 
                        "Structure {} already exists. Overwrite?".format(struct_name)):
            println("Aborted. Will not overwrite existing structure.")
            return
        println("Will overwrite existing structure: {}".format(struct_name))
    elif redefinition_mode:
        println("Updating existing structure: {}".format(struct_name))

    # Create the structure
    func_ptr_struct = StructureDataType(category_path, struct_name, 0, dtm)
    if target_namespace is not None and not target_namespace.isGlobal():
        func_ptr_struct.setDescription("Function Pointer Table Structure for namespace: {}".format(target_namespace.getName()))
    else:
        func_ptr_struct.setDescription("Function Pointer Table Structure")

    # Initialize monitoring
    if use_selection or redefinition_mode:
        monitor.initialize(expected_entries)
        if redefinition_mode:
            monitor.setMessage("Redefining {} existing entries...".format(expected_entries))
        else:
            monitor.setMessage("Processing {} selected entries...".format(expected_entries))
    else:
        monitor.initialize(100)  # Unknown count for auto-detect
        monitor.setMessage("Scanning for function pointers...")

    current_addr = start_addr
    entry_count = 0
    consecutive_nulls = 0
    processed_functions = set()  # Track processed functions to avoid duplicates
    
    println("Starting scan at address: {}".format(current_addr))
    
    while True:
        if monitor.isCancelled():
            println("Script cancelled during processing.")
            return
        
        # Check bounds based on selection or auto-detect mode
        if use_selection or redefinition_mode:
            # For selection mode, stop when we go beyond the end address
            if current_addr.compareTo(end_addr) > 0:
                println("Reached end of {} at: {}".format(
                    "structure" if redefinition_mode else "selection", end_addr))
                break
            # Also check if we would read beyond the selection
            if current_addr.add(pointer_size - 1).compareTo(end_addr) > 0:
                println("Next entry would exceed {} boundary".format(
                    "structure" if redefinition_mode else "selection"))
                break
        # For auto-detect mode, we rely on consecutive nulls to stop

        # Check if we can read a pointer at current address
        try:
            # Read pointer-sized data - try multiple approaches
            data = getDataAt(current_addr)
            target_addr = None
            
            # Method 1: Try to get value from existing data
            if data is not None and hasattr(data, 'getValue') and data.getValue() is not None:
                try:
                    target_addr = data.getValue()
                    println("Read pointer from existing data at {}: {}".format(current_addr, target_addr))
                except Exception as e:
                    println("Could not get value from existing data: {}".format(str(e)))
                    data = None
            
            # Method 2: If no data or couldn't get value, try creating pointer data
            if data is None or target_addr is None:
                try:
                    # Clear any existing data first
                    removeDataAt(current_addr)
                    # Create pointer data
                    createData(current_addr, PointerDataType.dataType)
                    data = getDataAt(current_addr)
                    if data is not None and hasattr(data, 'getValue'):
                        target_addr = data.getValue()
                        println("Created pointer data at {}: {}".format(current_addr, target_addr))
                except Exception as e:
                    println("Could not create pointer data: {}".format(str(e)))
                    data = None
            
            # Method 3: If still no success, read raw bytes
            if target_addr is None:
                try:
                    if pointer_size == 8:
                        raw_value = getLong(current_addr)
                    else:
                        raw_value = getInt(current_addr)
                    
                    # Handle negative values (convert to unsigned)
                    if raw_value < 0:
                        if pointer_size == 8:
                            raw_value = raw_value & 0xFFFFFFFFFFFFFFFF
                        else:
                            raw_value = raw_value & 0xFFFFFFFF
                    
                    target_addr = af.getAddress("0x{:x}".format(raw_value))
                    println("Read raw pointer value at {}: {}".format(current_addr, target_addr))
                except Exception as e:
                    println("Could not read raw pointer value at {}: {}".format(current_addr, str(e)))
                    consecutive_nulls += 1
                    if not use_selection and not redefinition_mode and consecutive_nulls >= max_consecutive_nulls:
                        break
                    current_addr = current_addr.add(pointer_size)
                    entry_count += 1
                    continue

            # Check if target address is valid and points to a function
            if target_addr is None or target_addr.getOffset() == 0:
                consecutive_nulls += 1
                println("Null pointer at entry {}: {}".format(entry_count, current_addr))
                # Add null pointer entry to structure
                null_ptr = PointerDataType(VoidDataType.dataType, pointer_size, dtm)
                func_ptr_struct.add(null_ptr, pointer_size, "null_{}".format(entry_count), "Null pointer")
            else:
                # Check if there's a function at the target address
                function = getFunctionAt(target_addr)
                
                # If no function exists, try to create one
                if function is None:
                    # Check if target looks like code (has instructions or is in executable memory)
                    instruction = getInstructionAt(target_addr)
                    memory_block = currentProgram.getMemory().getBlock(target_addr)
                    
                    is_executable = memory_block is not None and memory_block.isExecute()
                    
                    if instruction is not None or is_executable:
                        # Try to create a function at this address
                        try:
                            println("Creating function at: {}".format(target_addr))
                            function = createFunction(target_addr, None)
                            if function is not None:
                                println("Successfully created function: {}".format(function.getName()))
                        except Exception as e:
                            println("Could not create function at {}: {}".format(target_addr, str(e)))

                if function is not None:
                    consecutive_nulls = 0  # Reset null counter
                    
                    # Skip if we've already processed this function
                    func_addr = function.getEntryPoint()
                    if func_addr in processed_functions:
                        println("Function at {} already processed, skipping namespace/calling convention setup".format(func_addr))
                    else:
                        processed_functions.add(func_addr)
                        
                        # Set namespace for the function if target namespace is specified
                        if target_namespace is not None and not target_namespace.isGlobal():
                            try:
                                original_name = function.getName()
                                function.setParentNamespace(target_namespace)
                                new_name = function.getName()
                                println("Set function '{}' namespace to '{}' (full name: '{}')".format(
                                    original_name, target_namespace.getName(), new_name))
                            except Exception as e:
                                println("Warning: Could not set namespace for function '{}': {}".format(
                                    function.getName(), str(e)))
                        else:
                            println("Keeping function '{}' in global namespace".format(function.getName()))
                        
                        # Set calling convention
                        if auto_calling_conv:
                            try:
                                function.setCallingConvention(calling_convention)
                                println("Set calling convention '{}' for function '{}'".format(
                                    calling_convention, function.getName()))
                            except Exception as e:
                                println("Warning: Could not set calling convention for '{}': {}".format(
                                    function.getName(), str(e)))
                        
                        # Try to improve function analysis
                        try:
                            progloc = ProgramLocation(currentProgram, target_addr)
                            decompopts = DecompilerUtils.getDecompileOptions(state.getTool(), currentProgram)
                            cmd = FillOutStructureCmd(progloc, decompopts)
                            cmd.applyTo(currentProgram, monitor)
                            println("Applied decompiler analysis to function '{}'".format(function.getName()))
                        except Exception as e:
                            println("Warning: Decompiler analysis failed for '{}': {}".format(
                                function.getName(), str(e)))

                    # Create function definition and pointer type
                    try:
                        # Get the function signature
                        signature = function.getSignature(True)
                        
                        # Create a custom function definition with a clear name
                        func_def_name = function.getName()
                        if "::" in func_def_name:
                            func_def_name = func_def_name.split("::")[-1]  # Get last part after ::
                        
                        # Create function definition datatype
                        func_def_category = CategoryPath("/FunctionDefinitions")
                        if target_namespace is not None and not target_namespace.isGlobal():
                            func_def_category = CategoryPath("/FunctionDefinitions/{}".format(target_namespace.getName()))
                        
                        # Ensure category exists
                        if dtm.getCategory(func_def_category) is None:
                            try:
                                dtm.createCategory(func_def_category)
                            except:
                                func_def_category = CategoryPath("/FunctionDefinitions")
                        
                        # Create the function definition type
                        method_def = FunctionDefinitionDataType(func_def_category, func_def_name + "_def", dtm)
                        method_def.setReturnType(function.getReturnType())
                        
                        # Add parameters
                        params = function.getParameters()
                        for param in params:
                            method_def.addArgument(param.getDataType(), param.getName())
                        
                        # Set calling convention on the function definition
                        try:
                            method_def.setGenericCallingConvention(function.getCallingConventionName())
                        except:
                            pass
                        
                        # Resolve the function definition
                        method_def = dtm.resolve(method_def, DataTypeConflictHandler.REPLACE_HANDLER)
                        method_ptr_type = PointerDataType(method_def, pointer_size, dtm)
                        
                        # Determine field name - use simple function name without namespace prefix
                        field_name = function.getName()
                        if "::" in field_name:
                            field_name = field_name.split("::")[-1]  # Get last part after ::
                        if field_name.startswith("FUN_"):
                            field_name = "func_{}".format(entry_count)
                        
                        # Create meaningful comment
                        comment = "Function pointer to {}".format(function.getName(True))  # Full name with namespace
                        
                        func_ptr_struct.add(method_ptr_type, pointer_size, field_name, comment)
                        
                        println("Added function pointer {}: {} -> {} (def: {})".format(
                            entry_count, current_addr, function.getName(True), method_def.getName()))
                        
                    except Exception as e:
                        # Fallback: create simple function definition from signature
                        println("Warning: Could not create custom function definition for '{}': {}".format(
                            function.getName(), str(e)))
                        try:
                            signature = function.getSignature(True)
                            method_def = FunctionDefinitionDataType(signature, dtm)
                            method_def = dtm.resolve(method_def, DataTypeConflictHandler.KEEP_HANDLER)
                            method_ptr_type = PointerDataType(method_def, pointer_size, dtm)
                            
                            field_name = function.getName()
                            if "::" in field_name:
                                field_name = field_name.split("::")[-1]
                            if field_name.startswith("FUN_"):
                                field_name = "func_{}".format(entry_count)
                            
                            func_ptr_struct.add(method_ptr_type, pointer_size, field_name,
                                              "Function pointer to {}".format(function.getName(True)))
                            println("Added function pointer {}: {} -> {} (simple def)".format(
                                entry_count, current_addr, function.getName(True)))
                        except Exception as e2:
                            # Final fallback: add generic function pointer
                            println("Warning: Could not create any function definition for '{}': {}".format(
                                function.getName(), str(e2)))
                            generic_func_ptr = PointerDataType(VoidDataType.dataType, pointer_size, dtm)
                            field_name = function.getName()
                            if "::" in field_name:
                                field_name = field_name.split("::")[-1]
                            if field_name.startswith("FUN_"):
                                field_name = "func_{}".format(entry_count)
                            func_ptr_struct.add(generic_func_ptr, pointer_size, field_name,
                                              "Generic function pointer to {}".format(function.getName(True)))
                            println("Added generic function pointer {}: {} -> {}".format(
                                entry_count, current_addr, function.getName(True)))
                        
                else:
                    # Not a function - check if it might be data or code that we should try to make a function
                    instruction = getInstructionAt(target_addr)
                    data_at_target = getDataAt(target_addr)
                    memory_block = currentProgram.getMemory().getBlock(target_addr)
                    is_executable = memory_block is not None and memory_block.isExecute()
                    
                    if instruction is not None and is_executable:
                        # This looks like code but no function exists - try harder to create one
                        println("Found instructions at {} but no function - attempting to create function".format(target_addr))
                        try:
                            # Try disassembling first if needed
                            if getInstructionAt(target_addr) is None:
                                disassemble(target_addr)
                            
                            # Now try to create function
                            function = createFunction(target_addr, None)
                            if function is not None:
                                println("Successfully created function: {}".format(function.getName()))
                                
                                # Set namespace and calling convention for newly created function
                                if target_namespace is not None and not target_namespace.isGlobal():
                                    try:
                                        function.setParentNamespace(target_namespace)
                                        println("Set namespace for new function '{}'".format(function.getName()))
                                    except Exception as e:
                                        println("Warning: Could not set namespace for new function: {}".format(str(e)))
                                else:
                                    println("Keeping new function '{}' in global namespace".format(function.getName()))
                                
                                if auto_calling_conv:
                                    try:
                                        function.setCallingConvention(calling_convention)
                                    except:
                                        pass
                                
                                # Now process this function like any other
                                try:
                                    signature = function.getSignature(True)
                                    
                                    # Create function definition
                                    func_def_name = function.getName()
                                    if "::" in func_def_name:
                                        func_def_name = func_def_name.split("::")[-1]
                                    
                                    func_def_category = CategoryPath("/FunctionDefinitions")
                                    if target_namespace is not None and not target_namespace.isGlobal():
                                        func_def_category = CategoryPath("/FunctionDefinitions/{}".format(target_namespace.getName()))
                                    
                                    if dtm.getCategory(func_def_category) is None:
                                        try:
                                            dtm.createCategory(func_def_category)
                                        except:
                                            func_def_category = CategoryPath("/FunctionDefinitions")
                                    
                                    method_def = FunctionDefinitionDataType(func_def_category, func_def_name + "_def", dtm)
                                    method_def.setReturnType(function.getReturnType())
                                    
                                    params = function.getParameters()
                                    for param in params:
                                        method_def.addArgument(param.getDataType(), param.getName())
                                    
                                    try:
                                        method_def.setGenericCallingConvention(function.getCallingConventionName())
                                    except:
                                        pass
                                    
                                    method_def = dtm.resolve(method_def, DataTypeConflictHandler.REPLACE_HANDLER)
                                    method_ptr_type = PointerDataType(method_def, pointer_size, dtm)
                                    
                                    field_name = function.getName()
                                    if "::" in field_name:
                                        field_name = field_name.split("::")[-1]
                                    if field_name.startswith("FUN_"):
                                        field_name = "func_{}".format(entry_count)
                                    
                                    func_ptr_struct.add(method_ptr_type, pointer_size, field_name,
                                                      "Function pointer to {} (auto-created)".format(function.getName(True)))
                                    println("Added auto-created function pointer {}: {} -> {}".format(
                                        entry_count, current_addr, function.getName(True)))
                                    consecutive_nulls = 0
                                except Exception as e:
                                    # Fallback for auto-created function
                                    println("Warning: Could not create function definition for auto-created function: {}".format(str(e)))
                                    generic_func_ptr = PointerDataType(VoidDataType.dataType, pointer_size, dtm)
                                    func_ptr_struct.add(generic_func_ptr, pointer_size, "func_{}".format(entry_count),
                                                      "Generic pointer to auto-created function")
                                    consecutive_nulls = 0
                            else:
                                # Could not create function, treat as generic pointer
                                generic_ptr = PointerDataType(VoidDataType.dataType, pointer_size, dtm)
                                func_ptr_struct.add(generic_ptr, pointer_size, "ptr_{}".format(entry_count),
                                                  "Pointer to code at {}".format(target_addr))
                                println("Added code pointer {}: {} -> {} (could not create function)".format(
                                    entry_count, current_addr, target_addr))
                                consecutive_nulls = 0
                        except Exception as e:
                            println("Failed to create function at {}: {}".format(target_addr, str(e)))
                            generic_ptr = PointerDataType(VoidDataType.dataType, pointer_size, dtm)
                            func_ptr_struct.add(generic_ptr, pointer_size, "ptr_{}".format(entry_count),
                                              "Pointer to {}".format(target_addr))
                            consecutive_nulls = 0
                    elif data_at_target is not None or is_executable:
                        # Add as generic pointer
                        generic_ptr = PointerDataType(VoidDataType.dataType, pointer_size, dtm)
                        func_ptr_struct.add(generic_ptr, pointer_size, "ptr_{}".format(entry_count),
                                          "Pointer to {}".format(target_addr))
                        println("Added generic pointer {}: {} -> {}".format(
                            entry_count, current_addr, target_addr))
                        consecutive_nulls = 0
                    else:
                        consecutive_nulls += 1
                        println("Invalid target at entry {}: {} -> {}".format(
                            entry_count, current_addr, target_addr))
            
            # Check if we should stop due to consecutive nulls/invalids (only in auto-detect mode)
            if not use_selection and not redefinition_mode and consecutive_nulls >= max_consecutive_nulls:
                println("Stopping due to {} consecutive null/invalid entries".format(consecutive_nulls))
                break
            
            # Move to next entry
            entry_count += 1
            current_addr = current_addr.add(pointer_size)
            monitor.setProgress(entry_count)
            
        except Exception as e:
            printerr("Error processing entry {} at {}: {}".format(entry_count, current_addr, str(e)))
            # Add generic pointer entry even on error to maintain structure consistency
            try:
                generic_ptr = PointerDataType(VoidDataType.dataType, pointer_size, dtm)
                func_ptr_struct.add(generic_ptr, pointer_size, "error_{}".format(entry_count),
                                  "Error reading pointer at {}".format(current_addr))
                println("Added error placeholder for entry {}".format(entry_count))
            except Exception as e2:
                printerr("Could not even add error placeholder: {}".format(str(e2)))
            
            consecutive_nulls += 1
            if not use_selection and not redefinition_mode and consecutive_nulls >= max_consecutive_nulls:
                break
            current_addr = current_addr.add(pointer_size)
            entry_count += 1
    
    # Finalize structure
    if func_ptr_struct.getNumComponents() == 0:
        printerr("No valid function pointers found. Structure not created.")
        return
    
    # Add the structure to the data type manager
    try:
        added_type = dtm.resolve(func_ptr_struct, DataTypeConflictHandler.REPLACE_HANDLER)
        
        if added_type is not None:
            if redefinition_mode:
                println("Successfully redefined function pointer table structure: {}".format(added_type.getName()))
            else:
                println("Successfully created function pointer table structure: {}".format(added_type.getName()))
            println("Structure contains {} entries".format(added_type.getNumComponents()))
            if target_namespace is not None and not target_namespace.isGlobal():
                println("Functions organized under namespace: {}".format(target_namespace.getName()))
            else:
                println("Functions remain in global namespace")
            
            # Optionally apply the structure to the current location
            apply_prompt = "Apply Structure"
            apply_message = "Apply the {} structure to the start address ({})?".format(
                "updated" if redefinition_mode else "new", start_addr)
            
            if askYesNo(apply_prompt, apply_message):
                try:
                    # Clear existing data in the range first
                    clearListingAt = currentProgram.getListing().clearCodeUnits
                    if use_selection or redefinition_mode:
                        # Clear the entire selection range
                        address_set = currentProgram.getAddressFactory().getAddressSet(start_addr, end_addr)
                        clearListingAt(start_addr, end_addr, False)
                        println("Cleared existing data in selection range")
                    else:
                        # Clear just the structure size
                        struct_size = added_type.getLength()
                        end_clear_addr = start_addr.add(struct_size - 1)
                        clearListingAt(start_addr, end_clear_addr, False)
                        println("Cleared {} bytes of existing data".format(struct_size))
                    
                    # Now apply the structure
                    createData(start_addr, added_type)
                    println("Applied structure to address: {}".format(start_addr))
                except Exception as e:
                    printerr("Failed to apply structure: {}".format(str(e)))
                    # Try alternative approach - clear and apply one entry at a time
                    try:
                        println("Trying alternative approach...")
                        current_apply_addr = start_addr
                        for i in range(added_type.getNumComponents()):
                            try:
                                removeDataAt(current_apply_addr)
                                current_apply_addr = current_apply_addr.add(pointer_size)
                            except:
                                pass
                        # Now try to apply the structure again
                        createData(start_addr, added_type)
                        println("Successfully applied structure using alternative method")
                    except Exception as e2:
                        printerr("Alternative method also failed: {}".format(str(e2)))
        else:
            printerr("Failed to add structure to Data Type Manager.")
            
    except Exception as e:
        printerr("Error finalizing structure: {}".format(str(e)))

run()