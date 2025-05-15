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
from ghidra.program.model.listing import Variable
from ghidra.util.exception import CancelledException

def run():
    dtm = currentProgram.getDataTypeManager()
    pointer_size = currentProgram.getDefaultPointerSize()
    af = currentProgram.getAddressFactory()

    vftable_sym = getSymbolAt(currentAddress)

    print(str(type(vftable_sym)))
    if "NoneType" in str(type(vftable_sym)) or vftable_sym.getName() != "vftable":
        print("Errror not a valid vftable symbol selected")
        return


    category_path = CategoryPath("/ClassDataTypes")
    if dtm.getCategory(category_path) is None:
        try:
            dtm.createCategory(category_path)
            println("Created category: {}".format(category_path))
        except Exception as e:
            printerr("Failed to create category {}: {}".format(category_path, e))
            # Fallback to root category if creation fails
            category_path = CategoryPath.ROOT 
            println("Using root category instead.")

    struct_name = str(vftable_sym.getParentNamespace()).split(' ')[0] + "_vftable"
    print(struct_name)

    existing_struct = dtm.getDataType(category_path, struct_name)
    if existing_struct is not None:
        if not askYesNo("Overwrite Existing Structure?", 
                        "Structure {} in category {} already exists. Overwrite?".format(struct_name, category_path)):
            println("Aborted. Will not overwrite existing structure.")
            return
        println("Will overwrite existing structure: {}".format(struct_name))


    vtable_struct = StructureDataType(category_path, struct_name, 0, dtm)
    vtable_struct.setDescription(f"Virtual Function Table for {struct_name}")


    monitor.initialize(1)
    monitor.setMessage("Processing VTable Entries...")

    current_vtable_entry_addr = vftable_sym.getAddress()

    vftable_arr = getDataAt(vftable_sym.getAddress())
    num_elements = vftable_arr.getBaseDataType().getNumElements()

    for i in range(num_elements):
        if monitor.isCancelled():
            println("Script cancelled during processing.")
            return

        monitor.setProgress(i)
        primitive = vftable_arr.getPrimitiveAt(i*8)
        method_obj = getFunctionAt(primitive.value)

        if not method_obj:
            break

        method_obj.setCallingConvention("__thiscall")
        method_obj.setParentNamespace(vftable_sym.getParentNamespace())
        print(str(method_obj.getSignature(True)))

        if method_obj:
            method_def = FunctionDefinitionDataType(method_obj.getSignature(True), dtm)
            # Resolve the function definition type to ensure it's in the DTM
            method_def = dtm.resolve(method_def, DataTypeConflictHandler.KEEP_HANDLER)
            method_ptr_type = PointerDataType(method_def, pointer_size, dtm)
        else:
            member_sym = getSymbolAt(method_obj.value)

        vtable_struct.add(method_ptr_type, pointer_size, method_obj.name, f"Virtual Function Pointer for {method_obj.name}")

    added_type = dtm.resolve(vtable_struct, DataTypeConflictHandler.REPLACE_HANDLER)
    
    if added_type is not None:
        println("Successfully created/updated VTable structure: {} in category {}".format(
            added_type.getName(), added_type.getCategoryPath()
        ))
    else:
        printerr("Failed to add VTable structure to Data Type Manager.")

run()
