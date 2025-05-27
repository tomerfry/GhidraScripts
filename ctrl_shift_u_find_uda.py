# Look for potential uninitialized data access vulns
# @category Structure
# @keybinding ctrl shift u
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
    

    
run()
