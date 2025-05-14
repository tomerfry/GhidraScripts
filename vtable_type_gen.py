# Create a VTable structure from the current selection.
# @category Structure
# @keybinding ctrl shift q
# @menupath
# @toolbar
# @runtime PyGhidra

from ghidra.app.script import GhidraScript
from ghidra.program.model.data import (
    StructureDataType, PointerDataType, FunctionDefinitionDataType,
    DataTypeConflictHandler, CategoryPath, Undefined, VoidDataType
)
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import CancelledException
import re

class CreateVTableScript(GhidraScript):

    def sanitize_member_name(self, name):
        """
        Sanitizes a string to be a valid C structure member name.
        Replaces non-alphanumeric characters with underscores.
        Ensures the name does not start with a digit.
        """
        # Replace non-alphanumeric characters (and characters Ghidra might not like) with '_'
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        # Remove leading/trailing underscores that might result from replacements
        name = name.strip('_')
        # If the name becomes empty or is just underscores, provide a default
        if not name or name.count('_') == len(name):
            return None # Indicates a generic name should be used
        # Ensure it doesn't start with a digit
        if name[0].isdigit():
            name = '_' + name
        return name

    def run(self):
        if currentSelection is None or currentSelection.isEmpty():
            printerr("No selection found. Please select a memory region for the vtable.")
            return

        dtm = currentProgram.getDataTypeManager()
        pointer_size = currentProgram.getDefaultPointerSize()
        af = currentProgram.getAddressFactory()

        # Get the primary range of the selection
        # For vtables, we typically expect a single contiguous block.
        sel_min_addr = currentSelection.getMinAddress()
        sel_max_addr = currentSelection.getMaxAddress()
        
        # Calculate the total length of the selection in bytes
        # currentSelection.getNumAddresses() gives the number of selected bytes.
        selection_length = currentSelection.getNumAddresses()

        if selection_length == 0:
            printerr("Selection is empty (0 bytes).")
            return

        if selection_length % pointer_size != 0:
            printerr("Selection length ({}) is not a multiple of pointer size ({}).".format(
                selection_length, pointer_size
            ))
            printerr("Please select a region that is a multiple of the pointer size.")
            return

        num_entries = int(selection_length / pointer_size)
        println("Selected region: {} - {} ({} bytes, {} entries)".format(
            sel_min_addr, sel_min_addr.add(selection_length -1), selection_length, num_entries
        ))

        try:
            struct_name = askString("Enter VTable Structure Name", "VTableName")
            category_path_str = askString("Enter Category Path for VTable", "/VTABLES")
        except CancelledException:
            println("Script cancelled by user.")
            return

        category_path = CategoryPath(category_path_str)
        
        # Check if category exists, create if not
        if dtm.getCategory(category_path) is None:
            try:
                dtm.createCategory(category_path)
                println("Created category: {}".format(category_path_str))
            except Exception as e:
                printerr("Failed to create category {}: {}".format(category_path_str, e))
                # Fallback to root category if creation fails
                category_path = CategoryPath.ROOT 
                println("Using root category instead.")


        # Check if structure already exists
        existing_struct = dtm.getDataType(category_path, struct_name)
        if existing_struct is not None:
            if not askYesNo("Overwrite Existing Structure?", 
                            "Structure {} in category {} already exists. Overwrite?".format(struct_name, category_path_str)):
                println("Aborted. Will not overwrite existing structure.")
                return
            println("Will overwrite existing structure: {}".format(struct_name))


        vtable_struct = StructureDataType(category_path, struct_name, 0, dtm)
        vtable_struct.setDescription("VTable structure created from selection at {}".format(sel_min_addr))

        # To ensure unique member names if functions are unnamed or have conflicting names
        member_name_counts = {} 
        
        monitor.initialize(num_entries)
        monitor.setMessage("Processing VTable Entries...")

        current_vtable_entry_addr = sel_min_addr
        for i in range(num_entries):
            if monitor.isCancelled():
                println("Script cancelled during processing.")
                return

            monitor.setProgress(i)
            member_offset = i * pointer_size
            member_comment = ""
            member_name_base = "vfunc" # Default base name

            try:
                # Read the address stored at the current vtable entry
                if pointer_size == 4:
                    target_addr_long = getInt(current_vtable_entry_addr) 
                else:
                    target_addr_long = getLong(current_vtable_entry_addr)
                
                # Convert the long to an actual Address object
                # Handle potential negative values if target_addr_long is not sign-extended correctly by getInt/getLong for addresses
                # However, toAddr should handle this.
                target_func_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target_addr_long, True)

                member_comment = "Points to 0x{}".format(target_func_addr)
                func_ptr_type = PointerDataType(None, pointer_size, dtm) # Default: void*

                if target_func_addr is not None:
                    function = getFunctionAt(target_func_addr)
                    if function is not None:
                        # Try to get a sanitized name from the function
                        sanitized_func_name = self.sanitize_member_name(function.getName(True)) # True for original name
                        if sanitized_func_name:
                             member_name_base = sanitized_func_name
                        else: # Fallback if sanitization results in empty or invalid
                             member_name_base = "func_{:0X}".format(target_addr_long)


                        member_comment = "Points to {} at 0x{}".format(function.getName(True), target_func_addr)
                        
                        # Create a function definition for the pointer type
                        func_def = FunctionDefinitionDataType(function.getSignature(True), dtm)
                        # Resolve the function definition type to ensure it's in the DTM
                        func_def = dtm.resolve(func_def, DataTypeConflictHandler.KEEP_EXISTING_HANDLER)
                        func_ptr_type = PointerDataType(func_def, pointer_size, dtm)
                    else:
                        # No function, but we have a target address
                        member_name_base = "pfn_{:0X}".format(target_addr_long)
                        # Check if there's a label/symbol at the target address
                        symbol = getSymbolAt(target_func_addr)
                        if symbol:
                            sanitized_symbol_name = self.sanitize_member_name(symbol.getName())
                            if sanitized_symbol_name:
                                member_name_base = sanitized_symbol_name
                            member_comment = "Points to symbol {} at 0x{}".format(symbol.getName(), target_func_addr)
                        
                        # Use a generic void* or undefined* if no function info
                        # Using VoidDataType for a generic function pointer
                        void_dt = VoidDataType.dataType 
                        func_ptr_type = PointerDataType(void_dt, pointer_size, dtm)

                else: # target_func_addr is None (e.g. pointer value was 0)
                    member_comment = "Null pointer or invalid address"
                    member_name_base = "nullpfn"
                    # Use a generic void* for null pointers too
                    void_dt = VoidDataType.dataType
                    func_ptr_type = PointerDataType(void_dt, pointer_size, dtm)

            except Exception as e:
                # Error reading memory or processing entry
                printerr("Error processing entry at {}: {}".format(current_vtable_entry_addr, e))
                member_comment = "Error reading pointer data at 0x{}".format(current_vtable_entry_addr)
                member_name_base = "error_entry"
                # Use Undefined type for the pointer in case of error
                func_ptr_type = Undefined.getUndefinedDataType(pointer_size)


            # Ensure unique member name
            final_member_name = "{}_{}".format(member_name_base, hex(member_offset)[2:].zfill(2)) # e.g. MyMethod_00, MyMethod_04
            
            # More robust uniqueness:
            temp_name = member_name_base
            count = member_name_counts.get(temp_name, 0)
            if count > 0:
                final_member_name = "{}_{}".format(temp_name, count)
            else:
                final_member_name = temp_name
            member_name_counts[temp_name] = count + 1
            
            # Ghidra's structure editor might automatically rename if a direct name is invalid,
            # but providing a unique and somewhat valid one is better.
            # If `final_member_name` is still problematic, Ghidra will likely default it.

            vtable_struct.add(func_ptr_type, pointer_size, final_member_name, member_comment)
            current_vtable_entry_addr = current_vtable_entry_addr.add(pointer_size)

        # Add or replace the structure in the Data Type Manager
        added_type = dtm.resolve(vtable_struct, DataTypeConflictHandler.REPLACE_HANDLER)
        
        if added_type is not None:
            println("Successfully created/updated VTable structure: {} in category {}".format(
                added_type.getName(), added_type.getCategoryPath()
            ))

            if askYesNo("Apply Structure?", "Apply the new VTable structure '{}' at address {}?".format(added_type.getName(), sel_min_addr)):
                try:
                    # It's good practice to clear existing data first, especially if it's undefined or conflicting
                    # Be careful with clearListing as it can remove other analysis.
                    # A safer approach for vtables is often to just createData.
                    # clearListing(sel_min_addr, sel_min_addr.add(vtable_struct.getLength() - 1))
                    
                    # Create the data using the new structure
                    created_data = createData(sel_min_addr, added_type)
                    if created_data is not None:
                        println("Successfully applied structure {} at {}".format(added_type.getName(), sel_min_addr))
                    else:
                        printerr("Failed to apply structure at {}. It might be part of an existing instruction or defined data.".format(sel_min_addr))
                except Exception as e:
                    printerr("Error applying structure: {}".format(e))
            else:
                println("Structure not applied. You can find it in the Data Type Manager under {}.".format(category_path_str))
        else:
            printerr("Failed to add VTable structure to Data Type Manager.")

# Create an instance of the script and run it
# This is standard boilerplate for Ghidra Python scripts.
if __name__ == "__main__":
    # This part is for running the script from Ghidra's Script Manager
    # If you are running this in an external Python interpreter with ghidra_bridge,
    # you would instantiate and call run() differently.
    script = CreateVTableScript()
    try:
        script.run()
    except Exception as e:
        import traceback
        traceback.print_exc()
        script.printerr("Unhandled exception: " + str(e))


