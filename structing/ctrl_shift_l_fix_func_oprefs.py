# Fix Function operand references without created memory refs
# @category Structure
# @keybinding ctrl shift l
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
from ghidra.app.decompiler.util import FillOutStructureCmd
from ghidra.program.util import ProgramLocation
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.address import Address
from ghidra.program.model.symbol.RefType import READ

def run():
    f = getFunctionContaining(currentAddress)
    if not f:
        print(f"Error getting function at address {currentAddress}")
        return
    f_body = f.getBody()
    insts = currentProgram.getListing().getInstructions(f_body, True)
    for inst in insts:
        scalar = inst.getScalar(1)
        if not 'None' in str(type(scalar)):
            addr = addressFactory.getAddress(hex(scalar.value))
            if not 'None' in str(type(addr)):
                if currentProgram.memory.contains(addr):
                    print(f"Create Memory reference for {str(addr)} at instruction {str(inst)}")
                    createMemoryReference(inst, 1, addr, READ)

run()
