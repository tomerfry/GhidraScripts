#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

# Complete Interactive PyGhidra Taint Analysis Script with Highlighting
# Comprehensive checkbox UI with working buttons and visual taint tracking

from ghidra.program.model.symbol import *
from ghidra.program.model.listing import *
from ghidra.app.decompiler import *
from ghidra.program.model.pcode import *
from ghidra.util.task import *
from ghidra.program.model.address import *
from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from java.awt import Color
from javax.swing import *
from java.awt import *
from java.util import *

# Get the current program and location
program = currentProgram
location = currentLocation

# Define color schemes for different taint types
class TaintColors:
    SOURCE = Color(255, 200, 200)      # Light red for sources
    PROPAGATED = Color(255, 230, 200)  # Light orange for propagated
    SINK = Color(200, 200, 255)        # Light blue for sinks
    VULNERABILITY = Color(255, 100, 100) # Bright red for vulnerabilities
    PATH = Color(220, 220, 255)        # Light purple for taint paths

class ComprehensiveSourceSinkSelector:
    def __init__(self, function):
        self.function = function
        self.potential_sources = self._extract_potential_sources()
        self.potential_sinks = self._extract_potential_sinks()
        self.selected_sources = []  # Changed from set to list
        self.selected_sinks = []    # Changed from set to list
        self.source_checkboxes = []
        self.sink_checkboxes = []
        self.dialog_result = False
        
    def _extract_potential_sources(self):
        """Extract all potential taint sources"""
        sources = []
        
        # Function parameters
        print(f"DEBUG: Function {self.function.getName()} has {self.function.getParameterCount()} parameters")
        
        # Get parameters from function signature
        for i, param in enumerate(self.function.getParameters()):
            param_name = param.getName() if param.getName() else f"param_{i+1}"
            sources.append({
                'type': 'parameter',
                'name': param_name,
                'description': f"Parameter: {param_name} ({param.getDataType()})"
            })
            print(f"DEBUG: Found parameter: {param_name}")
        
        # Get parameters from decompiled function
        try:
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            decompiled = decompiler.decompileFunction(self.function, 30, TaskMonitor.DUMMY)
            
            if decompiled.decompileCompleted():
                high_function = decompiled.getHighFunction()
                if high_function:
                    local_symbol_map = high_function.getLocalSymbolMap()
                    param_names_found = set(param['name'] for param in sources)
                    
                    for symbol in local_symbol_map.getSymbols():
                        if symbol.isParameter():
                            param_name = symbol.getName()
                            if param_name not in param_names_found:
                                sources.append({
                                    'type': 'parameter',
                                    'name': param_name,
                                    'description': f"Parameter: {param_name} (from decompiler)"
                                })
                                print(f"DEBUG: Found additional parameter from decompiler: {param_name}")
        except Exception as e:
            print(f"DEBUG: Error getting parameters from decompiler: {e}")
        
        # Global variables
        globals_found = set()
        instruction_iter = program.getListing().getInstructions(self.function.getBody(), True)
        for instruction in instruction_iter:
            for ref in instruction.getReferencesFrom():
                if ref.getReferenceType().isData():
                    symbol = program.getSymbolTable().getPrimarySymbol(ref.getToAddress())
                    if symbol and symbol.isGlobal() and not symbol.isExternal():
                        global_name = symbol.getName()
                        if global_name not in globals_found:
                            globals_found.add(global_name)
                            sources.append({
                                'type': 'global',
                                'name': global_name,
                                'description': f"Global variable: {global_name}"
                            })
        
        # Function calls that could return tainted data
        calls_found = set()
        for instruction in program.getListing().getInstructions(self.function.getBody(), True):
            if instruction.getFlowType().isCall():
                for ref in instruction.getReferencesFrom():
                    if ref.getReferenceType().isCall():
                        called_func = program.getFunctionManager().getFunctionAt(ref.getToAddress())
                        if called_func and called_func.getName() not in calls_found:
                            calls_found.add(called_func.getName())
                            sources.append({
                                'type': 'function_return',
                                'name': called_func.getName(),
                                'description': f"Return value from: {called_func.getName()}"
                            })
        
        print(f"DEBUG: Total sources found: {len(sources)}")
        return sources
    
    def _extract_potential_sinks(self):
        """Extract all potential taint sinks"""
        sinks = []
        
        # Function calls (arguments can be sinks)
        calls_found = set()
        for instruction in program.getListing().getInstructions(self.function.getBody(), True):
            if instruction.getFlowType().isCall():
                for ref in instruction.getReferencesFrom():
                    if ref.getReferenceType().isCall():
                        called_func = program.getFunctionManager().getFunctionAt(ref.getToAddress())
                        if called_func and called_func.getName() not in calls_found:
                            calls_found.add(called_func.getName())
                            sinks.append({
                                'type': 'function_call',
                                'name': called_func.getName(),
                                'description': f"Arguments to: {called_func.getName()}"
                            })
        
        # Memory operations and other sinks
        sinks.extend([
            {'type': 'memory_write', 'name': 'memory_stores', 'description': 'Memory write operations (STORE)'},
            {'type': 'memory_read', 'name': 'memory_loads', 'description': 'Memory read operations (LOAD)'},
            {'type': 'indirect_call', 'name': 'indirect_calls', 'description': 'Indirect function calls'},
            {'type': 'return_value', 'name': 'function_return', 'description': 'Function return value'},
            {'type': 'array_index', 'name': 'array_indexing', 'description': 'Array/pointer indexing operations'}
        ])
        
        return sinks
    
    def show_selection_dialog(self):
        """Show comprehensive source/sink selection dialog with checkboxes"""
        dialog = JDialog()
        dialog.setTitle(f"Comprehensive Taint Analysis - {self.function.getName()}")
        dialog.setModal(True)
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE)
        dialog.setLayout(BorderLayout())
        
        # Instructions panel
        instructions = JTextArea(
            f"Comprehensive Taint Analysis Configuration\n" +
            f"Function: {self.function.getName()}\n\n" +
            "SOURCES (introduce tainted data):\n" +
            "- Function parameters\n" +
            "- Global variables\n" +
            "- Function return values\n\n" +
            "SINKS (potentially dangerous data usage):\n" +
            "- Function call arguments\n" +
            "- Memory operations\n" +
            "- Return values and indirect calls\n\n" +
            "Use checkboxes to select multiple items:\n" +
            "Tainted elements will be highlighted in the decompiler view."
        )
        instructions.setEditable(False)
        instructions.setRows(10)
        instructions.setFont(Font("Monospaced", Font.PLAIN, 11))
        dialog.add(JScrollPane(instructions), BorderLayout.NORTH)
        
        # Main panel with source/sink selection
        main_panel = JPanel(GridLayout(1, 2, 10, 0))
        
        # Sources panel with checkboxes
        sources_panel = JPanel(BorderLayout())
        sources_panel.add(JLabel("Select SOURCES (check multiple):"), BorderLayout.NORTH)
        
        sources_checkbox_panel = JPanel()
        sources_checkbox_panel.setLayout(BoxLayout(sources_checkbox_panel, BoxLayout.Y_AXIS))
        
        self.source_checkboxes = []
        for i, source in enumerate(self.potential_sources):
            checkbox = JCheckBox(source['description'])
            checkbox.putClientProperty("source_index", i)
            self.source_checkboxes.append(checkbox)
            sources_checkbox_panel.add(checkbox)
        
        sources_scroll = JScrollPane(sources_checkbox_panel)
        sources_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        sources_panel.add(sources_scroll, BorderLayout.CENTER)
        
        # Sinks panel with checkboxes
        sinks_panel = JPanel(BorderLayout())
        sinks_panel.add(JLabel("Select SINKS (check multiple):"), BorderLayout.NORTH)
        
        sinks_checkbox_panel = JPanel()
        sinks_checkbox_panel.setLayout(BoxLayout(sinks_checkbox_panel, BoxLayout.Y_AXIS))
        
        self.sink_checkboxes = []
        for i, sink in enumerate(self.potential_sinks):
            checkbox = JCheckBox(sink['description'])
            checkbox.putClientProperty("sink_index", i)
            self.sink_checkboxes.append(checkbox)
            sinks_checkbox_panel.add(checkbox)
        
        sinks_scroll = JScrollPane(sinks_checkbox_panel)
        sinks_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        sinks_panel.add(sinks_scroll, BorderLayout.CENTER)
        
        main_panel.add(sources_panel)
        main_panel.add(sinks_panel)
        dialog.add(main_panel, BorderLayout.CENTER)
        
        # Buttons panel
        buttons_panel = JPanel(FlowLayout())
        
        # Preset buttons
        preset_panel = JPanel(FlowLayout())
        preset_panel.add(JLabel("Presets:"))
        
        all_params_btn = JButton("All Parameters")
        all_params_btn.addActionListener(self._select_all_parameters)
        preset_panel.add(all_params_btn)
        
        dangerous_sinks_btn = JButton("Dangerous Sinks") 
        dangerous_sinks_btn.addActionListener(self._select_dangerous_sinks)
        preset_panel.add(dangerous_sinks_btn)
        
        all_sinks_btn = JButton("All Sinks")
        all_sinks_btn.addActionListener(self._select_all_sinks)
        preset_panel.add(all_sinks_btn)
        
        clear_btn = JButton("Clear All")
        clear_btn.addActionListener(self._clear_selections)
        preset_panel.add(clear_btn)
        
        buttons_panel.add(preset_panel)
        
        # OK/Cancel buttons - Fixed the Start Analysis button
        ok_btn = JButton("Start Analysis")
        ok_btn.addActionListener(self._on_ok_button)
        
        cancel_btn = JButton("Cancel")
        cancel_btn.addActionListener(lambda e: dialog.dispose())
        
        buttons_panel.add(ok_btn)
        buttons_panel.add(cancel_btn)
        
        dialog.add(buttons_panel, BorderLayout.SOUTH)
        
        # Store dialog reference for the OK button
        self.current_dialog = dialog
        
        # Show dialog
        dialog.setSize(900, 700)
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)
        
        return self.dialog_result
    
    def _select_all_parameters(self, event=None):
        """Select all function parameters as sources"""
        for checkbox in self.source_checkboxes:
            source_index = checkbox.getClientProperty("source_index")
            if source_index is not None and self.potential_sources[source_index]['type'] == 'parameter':
                checkbox.setSelected(True)
    
    def _select_dangerous_sinks(self, event=None):
        """Select commonly dangerous sinks"""
        dangerous_types = {'function_call', 'memory_write', 'indirect_call', 'array_index'}
        for checkbox in self.sink_checkboxes:
            sink_index = checkbox.getClientProperty("sink_index")
            if sink_index is not None and self.potential_sinks[sink_index]['type'] in dangerous_types:
                checkbox.setSelected(True)
    
    def _select_all_sinks(self, event=None):
        """Select all sinks"""
        for checkbox in self.sink_checkboxes:
            checkbox.setSelected(True)
    
    def _clear_selections(self, event=None):
        """Clear all selections"""
        for checkbox in self.source_checkboxes:
            checkbox.setSelected(False)
        for checkbox in self.sink_checkboxes:
            checkbox.setSelected(False)
    
    def _on_ok_button(self, event=None):
        """Handle OK button click - separate method to avoid lambda issues"""
        try:
            # Get selected sources from checkboxes
            self.selected_sources = []  # Use list instead of set
            for checkbox in self.source_checkboxes:
                if checkbox.isSelected():
                    source_index = checkbox.getClientProperty("source_index")
                    if source_index is not None:
                        self.selected_sources.append(self.potential_sources[source_index])
            
            # Get selected sinks from checkboxes
            self.selected_sinks = []  # Use list instead of set
            for checkbox in self.sink_checkboxes:
                if checkbox.isSelected():
                    sink_index = checkbox.getClientProperty("sink_index")
                    if sink_index is not None:
                        self.selected_sinks.append(self.potential_sinks[sink_index])
            
            # Set result flag
            self.dialog_result = len(self.selected_sources) > 0 or len(self.selected_sinks) > 0
            
            # Close dialog
            self.current_dialog.dispose()
            
        except Exception as e:
            print(f"Error in OK button handler: {e}")
            import traceback
            traceback.print_exc()

class ComprehensiveTaintAnalyzer:
    def __init__(self):
        self.program = program
        self.decompiler = self._setup_decompiler()
        self.tainted_varnodes = set()
        self.varnode_info = {}
        self.taint_paths = []
        self.source_config = []  # Changed from set to list
        self.sink_config = []    # Changed from set to list
        self.highlighted_addresses = set()  # Track highlighted addresses
        self.colorizer = self._get_colorizer_service()
        
    def _setup_decompiler(self):
        """Initialize the decompiler interface"""
        decompiler = DecompInterface()
        decompiler.openProgram(self.program)
        return decompiler
    
    def _get_colorizer_service(self):
        """Get the colorizer service for highlighting"""
        try:
            from ghidra.app.plugin.core.colorizer import ColorizingService
            tool = state.getTool()
            return tool.getService(ColorizingService)
        except:
            print("Warning: Could not get colorizer service. Highlighting will be limited.")
            return None
    
    def clear_highlights(self):
        """Clear all existing highlights"""
        if self.colorizer:
            try:
                # Clear all addresses we've highlighted
                for addr in self.highlighted_addresses:
                    self.colorizer.clearBackgroundColor(addr, addr)
                self.highlighted_addresses.clear()
            except Exception as e:
                print(f"Error clearing highlights: {e}")
    
    def highlight_address(self, address, color, description=""):
        """Highlight an address with the specified color"""
        if self.colorizer and address:
            try:
                self.colorizer.setBackgroundColor(address, address, color)
                self.highlighted_addresses.add(address)
                if description:
                    print(f"  Highlighted {address} ({description})")
            except Exception as e:
                print(f"Error highlighting address {address}: {e}")
    
    def analyze_current_function(self):
        """Analyze the currently selected function"""
        if not location:
            JOptionPane.showMessageDialog(None, 
                "No location selected. Please position cursor in a function.",
                "Error", JOptionPane.ERROR_MESSAGE)
            return False
            
        current_function = self.program.getFunctionManager().getFunctionContaining(location.getAddress())
        if not current_function:
            JOptionPane.showMessageDialog(None,
                "No function found at current location.",
                "Error", JOptionPane.ERROR_MESSAGE)
            return False
        
        # Show source/sink selection
        selector = ComprehensiveSourceSinkSelector(current_function)
        if not selector.show_selection_dialog():
            print("Analysis cancelled by user.")
            return False
        
        self.source_config = selector.selected_sources
        self.sink_config = selector.selected_sinks
        
        # Print configuration
        print(f"=== Comprehensive Taint Analysis ===")
        print(f"Function: {current_function.getName()}")
        print(f"Address: {current_function.getEntryPoint()}")
        
        print(f"\nSelected Sources ({len(self.source_config)}):")
        for source in self.source_config:
            print(f"  {source['type']}: {source['name']}")
        
        print(f"\nSelected Sinks ({len(self.sink_config)}):")
        for sink in self.sink_config:
            print(f"  {sink['type']}: {sink['name']}")
        
        print()
        
        return self.analyze_function(current_function)
    
    def analyze_function(self, function):
        """Perform comprehensive taint analysis"""
        # Clear any existing highlights
        self.clear_highlights()
        
        # Reset state
        self.tainted_varnodes.clear()
        self.varnode_info.clear()
        self.taint_paths.clear()
        
        # Store function for later use
        self.current_function = function
        
        # Get decompiled function
        decompiled = self.decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
        if not decompiled.decompileCompleted():
            print(f"ERROR: Failed to decompile {function.getName()}")
            return False
            
        high_function = decompiled.getHighFunction()
        if not high_function:
            print("ERROR: No high-level function representation available")
            return False
        
        print("--- Initializing Taint Sources ---")
        self._initialize_sources(high_function)
        
        print("\n--- Data Flow Analysis ---")
        self._analyze_data_flow(high_function)
        
        print("\n--- Applying Visual Highlights ---")
        self._apply_highlights(high_function)
        
        print(f"\n--- Summary ---")
        vulnerabilities = self._count_vulnerabilities()
        print(f"Total tainted varnodes: {len(self.tainted_varnodes)}")
        print(f"Potential vulnerabilities: {vulnerabilities}")
        print(f"Taint propagation paths: {len(self.taint_paths)}")
        print(f"Highlighted addresses: {len(self.highlighted_addresses)}")
        
        if vulnerabilities > 0:
            JOptionPane.showMessageDialog(None,
                f"Found {vulnerabilities} potential vulnerabilities!\nCheck console output, bookmarks, and highlighted code.",
                "Vulnerabilities Found", JOptionPane.WARNING_MESSAGE)
        
        return True
    
    def _initialize_sources(self, high_function):
        """Initialize taint sources based on user selection"""
        local_symbol_map = high_function.getLocalSymbolMap()
        
        for source in self.source_config:
            if source['type'] == 'parameter':
                param_name = source['name']
                for symbol in local_symbol_map.getSymbols():
                    if symbol.isParameter() and symbol.getName() == param_name:
                        high_var = symbol.getHighVariable()
                        if high_var:
                            param_varnode = high_var.getRepresentative()
                            if param_varnode:
                                self.tainted_varnodes.add(param_varnode.getUniqueId())
                                self.varnode_info[param_varnode.getUniqueId()] = {
                                    'type': 'source',
                                    'source_type': 'parameter',
                                    'name': param_name,
                                    'description': f"Parameter: {param_name}",
                                    'varnode': param_varnode,
                                    'high_var': high_var
                                }
                                print(f"  TAINT SOURCE: Parameter {param_name} -> {param_varnode}")
            
            elif source['type'] == 'global':
                print(f"  TAINT SOURCE: Global variable {source['name']} (marked for tracking)")
            
            elif source['type'] == 'function_return':
                print(f"  TAINT SOURCE: Return value from {source['name']} (marked for tracking)")
    
    def _analyze_data_flow(self, high_function):
        """Comprehensive data flow analysis"""
        # Get all PCode operations
        pcode_ops = []
        try:
            for basic_block in high_function.getBasicBlocks():
                op_iter = basic_block.getIterator()
                while op_iter.hasNext():
                    pcode_ops.append(op_iter.next())
        except Exception as e:
            print(f"Error getting PCode operations: {e}")
            return
        
        print(f"Analyzing {len(pcode_ops)} PCode operations...")
        
        # Process each operation
        for i, pcode_op in enumerate(pcode_ops):
            try:
                self._process_pcode_operation(pcode_op, i)
            except Exception as e:
                print(f"Error processing operation {i}: {e}")
    
    def _process_pcode_operation(self, pcode_op, op_index):
        """Process PCode operations with comprehensive taint tracking"""
        opcode = pcode_op.getOpcode()
        
        try:
            address = pcode_op.getSeqnum().getTarget()
        except:
            address = None
        
        if opcode == PcodeOp.CALL:
            self._handle_function_call(pcode_op, op_index, address)
        elif opcode == PcodeOp.CALLIND:
            self._handle_indirect_call(pcode_op, op_index, address)
        elif opcode == PcodeOp.COPY:
            self._handle_copy_operation(pcode_op, op_index, address)
        elif opcode == PcodeOp.LOAD:
            self._handle_load_operation(pcode_op, op_index, address)
        elif opcode == PcodeOp.STORE:
            self._handle_store_operation(pcode_op, op_index, address)
        elif opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, 
                       PcodeOp.INT_DIV, PcodeOp.INT_AND, PcodeOp.INT_OR]:
            self._handle_arithmetic_operation(pcode_op, op_index, address)
        elif opcode == PcodeOp.RETURN:
            self._handle_return_operation(pcode_op, op_index, address)
    
    def _handle_function_call(self, pcode_op, op_index, address):
        """Handle function calls"""
        if pcode_op.getNumInputs() == 0:
            return
            
        target = pcode_op.getInput(0)
        
        if target and target.isAddress():
            called_func = self.program.getFunctionManager().getFunctionAt(target.getAddress())
            if called_func:
                func_name = called_func.getName()
                
                # Check if this function return should be a taint source
                for source in self.source_config:
                    if source['type'] == 'function_return' and source['name'] == func_name:
                        output_var = pcode_op.getOutput()
                        if output_var:
                            self.tainted_varnodes.add(output_var.getUniqueId())
                            self.varnode_info[output_var.getUniqueId()] = {
                                'type': 'source',
                                'source_type': 'function_return',
                                'name': func_name,
                                'description': f"Return from {func_name}",
                                'address': address,
                                'varnode': output_var
                            }
                            print(f"[{op_index:3d}] TAINT SOURCE: {func_name} -> {output_var}")
                            self.taint_paths.append(f"Function return: {func_name} -> varnode {output_var.getUniqueId()}")
                
                # Check for sink function calls
                for sink in self.sink_config:
                    if sink['type'] == 'function_call' and sink['name'] == func_name:
                        tainted_args = []
                        for i in range(1, pcode_op.getNumInputs()):
                            input_var = pcode_op.getInput(i)
                            if input_var and input_var.getUniqueId() in self.tainted_varnodes:
                                tainted_args.append((i, input_var))
                        
                        if tainted_args:
                            print(f"[{op_index:3d}] *** VULNERABILITY: Tainted data flows to {func_name} ***")
                            for arg_idx, arg_var in tainted_args:
                                print(f"    Tainted arg {arg_idx}: {arg_var}")
                                if arg_var.getUniqueId() in self.varnode_info:
                                    self.varnode_info[arg_var.getUniqueId()]['vulnerability'] = f'tainted_arg_to_{func_name}'
                                    self.varnode_info[arg_var.getUniqueId()]['vuln_address'] = address
                            
                            if address:
                                self._create_bookmark(address, f"Tainted data flows to {func_name}")
    
    def _handle_indirect_call(self, pcode_op, op_index, address):
        """Handle indirect calls"""
        if pcode_op.getNumInputs() == 0:
            return
            
        target = pcode_op.getInput(0)
        
        # Check if indirect calls are configured as sinks
        for sink in self.sink_config:
            if sink['type'] == 'indirect_call':
                if target and target.getUniqueId() in self.tainted_varnodes:
                    print(f"[{op_index:3d}] *** CRITICAL: Indirect call with tainted function pointer ***")
                    if target.getUniqueId() in self.varnode_info:
                        self.varnode_info[target.getUniqueId()]['vulnerability'] = 'indirect_call_tainted_pointer'
                        self.varnode_info[target.getUniqueId()]['vuln_address'] = address
                    
                    if address:
                        self._create_bookmark(address, "CRITICAL: Tainted function pointer")
    
    def _handle_copy_operation(self, pcode_op, op_index, address):
        """Handle assignments/copies"""
        if pcode_op.getNumInputs() == 0:
            return
            
        input_var = pcode_op.getInput(0)
        output_var = pcode_op.getOutput()
        
        if input_var and output_var and input_var.getUniqueId() in self.tainted_varnodes:
            # Propagate taint
            self.tainted_varnodes.add(output_var.getUniqueId())
            
            # Copy and update info
            if input_var.getUniqueId() in self.varnode_info:
                self.varnode_info[output_var.getUniqueId()] = self.varnode_info[input_var.getUniqueId()].copy()
                self.varnode_info[output_var.getUniqueId()]['type'] = 'propagated'
                self.varnode_info[output_var.getUniqueId()]['address'] = address
                self.varnode_info[output_var.getUniqueId()]['varnode'] = output_var
            
            print(f"[{op_index:3d}] *** TAINT PROPAGATION: {input_var} -> {output_var} ***")
            self.taint_paths.append(f"Copy propagation: {input_var.getUniqueId()} -> {output_var.getUniqueId()}")
    
    def _handle_load_operation(self, pcode_op, op_index, address):
        """Handle memory loads"""
        if pcode_op.getNumInputs() < 2:
            return
            
        addr_var = pcode_op.getInput(1)
        output_var = pcode_op.getOutput()
        
        if addr_var and output_var and addr_var.getUniqueId() in self.tainted_varnodes:
            self.tainted_varnodes.add(output_var.getUniqueId())
            self.varnode_info[output_var.getUniqueId()] = {
                'type': 'load_from_tainted',
                'source': 'memory_load',
                'description': f"Load from tainted address",
                'address': address,
                'varnode': output_var
            }
            print(f"[{op_index:3d}] *** TAINT PROPAGATION: LOAD *{addr_var} -> {output_var} ***")
            self.taint_paths.append(f"Load from tainted address: {addr_var.getUniqueId()} -> {output_var.getUniqueId()}")
    
    def _handle_store_operation(self, pcode_op, op_index, address):
        """Handle memory stores"""
        if pcode_op.getNumInputs() < 3:
            return
            
        addr_var = pcode_op.getInput(1)
        value_var = pcode_op.getInput(2)
        
        # Check if memory writes are configured as sinks
        for sink in self.sink_config:
            if sink['type'] == 'memory_write':
                if value_var and value_var.getUniqueId() in self.tainted_varnodes:
                    print(f"[{op_index:3d}] *** VULNERABILITY: STORE tainted value -> *{addr_var} ***")
                    if value_var.getUniqueId() in self.varnode_info:
                        self.varnode_info[value_var.getUniqueId()]['vulnerability'] = 'tainted_memory_write'
                        self.varnode_info[value_var.getUniqueId()]['vuln_address'] = address
                    self.taint_paths.append(f"Store tainted value: {value_var.getUniqueId()} -> memory")
                    
                    if address:
                        self._create_bookmark(address, "Tainted data written to memory")
    
    def _handle_arithmetic_operation(self, pcode_op, op_index, address):
        """Handle arithmetic operations"""
        output_var = pcode_op.getOutput()
        
        # Check for tainted inputs
        tainted_inputs = []
        for i in range(pcode_op.getNumInputs()):
            input_var = pcode_op.getInput(i)
            if input_var and input_var.getUniqueId() in self.tainted_varnodes:
                tainted_inputs.append(input_var)
        
        if tainted_inputs and output_var:
            self.tainted_varnodes.add(output_var.getUniqueId())
            self.varnode_info[output_var.getUniqueId()] = {
                'type': 'arithmetic',
                'source': 'derived_from_tainted',
                'description': f"Arithmetic result from tainted data",
                'address': address,
                'varnode': output_var
            }
            op_name = self._get_operation_name(pcode_op.getOpcode())
            print(f"[{op_index:3d}] *** TAINT PROPAGATION: {op_name} -> {output_var} ***")
            self.taint_paths.append(f"Arithmetic propagation: {op_name} -> {output_var.getUniqueId()}")
    
    def _handle_return_operation(self, pcode_op, op_index, address):
        """Handle function returns"""
        if pcode_op.getNumInputs() > 0:
            return_var = pcode_op.getInput(0)
            if return_var and return_var.getUniqueId() in self.tainted_varnodes:
                # Check if return value is configured as sink
                for sink in self.sink_config:
                    if sink['type'] == 'return_value':
                        print(f"[{op_index:3d}] *** VULNERABILITY: TAINTED RETURN VALUE ***")
                        if return_var.getUniqueId() in self.varnode_info:
                            self.varnode_info[return_var.getUniqueId()]['vulnerability'] = 'tainted_return_value'
                            self.varnode_info[return_var.getUniqueId()]['vuln_address'] = address
                        self.taint_paths.append(f"Function returns tainted value: {return_var.getUniqueId()}")
                        
                        if address:
                            self._create_bookmark(address, "Function returns tainted data")
    
    def _get_operation_name(self, opcode):
        """Get readable operation name"""
        op_names = {
            PcodeOp.INT_ADD: "ADD",
            PcodeOp.INT_SUB: "SUB", 
            PcodeOp.INT_MULT: "MULT",
            PcodeOp.INT_DIV: "DIV",
            PcodeOp.INT_AND: "AND",
            PcodeOp.INT_OR: "OR"
        }
        return op_names.get(opcode, f"OP_{opcode}")
    
    def _create_bookmark(self, address, comment):
        """Create bookmark for vulnerabilities"""
        try:
            bookmark_manager = self.program.getBookmarkManager()
            bookmark_manager.setBookmark(address, BookmarkType.ANALYSIS, "Taint", comment)
            print(f"      -> Bookmark created at {address}")
        except Exception as e:
            print(f"      -> Could not create bookmark: {e}")
    
    def _apply_highlights(self, high_function):
        """Apply visual highlights to tainted elements"""
        print("\nApplying visual highlights...")
        
        # First, collect all addresses associated with tainted varnodes
        address_to_taint_type = {}
        
        for varnode_id, info in self.varnode_info.items():
            if varnode_id not in self.tainted_varnodes:
                continue
                
            # Get addresses from stored information
            if 'address' in info and info['address']:
                addr = info['address']
                taint_type = info.get('type', 'unknown')
                
                # Determine priority (vulnerabilities have highest priority)
                if 'vulnerability' in info:
                    address_to_taint_type[addr] = 'vulnerability'
                elif addr not in address_to_taint_type or taint_type == 'source':
                    address_to_taint_type[addr] = taint_type
        
        # Also highlight instructions that use tainted varnodes
        try:
            # Get all PCode operations again to find instruction addresses
            for basic_block in high_function.getBasicBlocks():
                op_iter = basic_block.getIterator()
                while op_iter.hasNext():
                    pcode_op = op_iter.next()
                    try:
                        address = pcode_op.getSeqnum().getTarget()
                        if address:
                            # Check if this operation uses tainted varnodes
                            uses_tainted = False
                            taint_type = 'propagated'
                            
                            # Check inputs
                            for i in range(pcode_op.getNumInputs()):
                                input_var = pcode_op.getInput(i)
                                if input_var and input_var.getUniqueId() in self.tainted_varnodes:
                                    uses_tainted = True
                                    if input_var.getUniqueId() in self.varnode_info:
                                        var_info = self.varnode_info[input_var.getUniqueId()]
                                        if 'vulnerability' in var_info:
                                            taint_type = 'vulnerability'
                                        elif var_info.get('type') == 'source' and taint_type != 'vulnerability':
                                            taint_type = 'source'
                            
                            # Check output
                            output_var = pcode_op.getOutput()
                            if output_var and output_var.getUniqueId() in self.tainted_varnodes:
                                uses_tainted = True
                                if output_var.getUniqueId() in self.varnode_info:
                                    var_info = self.varnode_info[output_var.getUniqueId()]
                                    if 'vulnerability' in var_info:
                                        taint_type = 'vulnerability'
                                    elif var_info.get('type') == 'source' and taint_type != 'vulnerability':
                                        taint_type = 'source'
                            
                            if uses_tainted:
                                # Update the address mapping with higher priority types
                                if address not in address_to_taint_type or taint_type == 'vulnerability':
                                    address_to_taint_type[address] = taint_type
                                elif taint_type == 'source' and address_to_taint_type[address] == 'propagated':
                                    address_to_taint_type[address] = taint_type
                    
                    except:
                        pass
        except Exception as e:
            print(f"Error processing operations for highlighting: {e}")
        
        # Apply highlights based on taint type
        highlighted_count = 0
        for addr, taint_type in address_to_taint_type.items():
            if taint_type == 'vulnerability':
                self.highlight_address(addr, TaintColors.VULNERABILITY, "Vulnerability")
                highlighted_count += 1
            elif taint_type == 'source':
                self.highlight_address(addr, TaintColors.SOURCE, "Taint source")
                highlighted_count += 1
            elif taint_type == 'propagated':
                self.highlight_address(addr, TaintColors.PROPAGATED, "Taint propagation")
                highlighted_count += 1
            elif taint_type == 'sink':
                self.highlight_address(addr, TaintColors.SINK, "Taint sink")
                highlighted_count += 1
            else:
                self.highlight_address(addr, TaintColors.PATH, "Taint path")
                highlighted_count += 1
        
        print(f"Highlighted {highlighted_count} addresses")
        
        # Also highlight the entry point of tainted parameters
        for source in self.source_config:
            if source['type'] == 'parameter':
                # Highlight function entry for parameter sources
                entry_addr = self.current_function.getEntryPoint()
                self.highlight_address(entry_addr, TaintColors.SOURCE, f"Entry: tainted parameter {source['name']}")
    
    def _count_vulnerabilities(self):
        """Count vulnerabilities found"""
        count = 0
        for varnode_id, info in self.varnode_info.items():
            if 'vulnerability' in info:
                count += 1
        return count
    
    def print_comprehensive_summary(self):
        """Print comprehensive analysis summary"""
        if not self.tainted_varnodes:
            print("No tainted data found in this function.")
            return
        
        print(f"\n=== Comprehensive Taint Analysis Summary ===")
        
        # Categorize tainted varnodes
        sources = []
        propagated = []
        vulnerabilities = []
        
        for varnode_id in self.tainted_varnodes:
            if varnode_id in self.varnode_info:
                info = self.varnode_info[varnode_id]
                if info.get('type') == 'source':
                    sources.append((varnode_id, info))
                elif 'vulnerability' in info:
                    vulnerabilities.append((varnode_id, info))
                else:
                    propagated.append((varnode_id, info))
        
        # Print sources
        print(f"\n*** TAINT SOURCES ({len(sources)}) ***")
        for varnode_id, info in sources:
            print(f"  ID {varnode_id}: {info.get('description', info)}")
        
        # Print vulnerabilities
        if vulnerabilities:
            print(f"\n*** VULNERABILITIES FOUND ({len(vulnerabilities)}) ***")
            for varnode_id, info in vulnerabilities:
                vuln_type = info.get('vulnerability', 'Unknown vulnerability')
                print(f"  ID {varnode_id}: {vuln_type}")
                print(f"    {info.get('description', '')}")
                if 'vuln_address' in info:
                    print(f"    Address: {info['vuln_address']}")
        
        # Print propagation summary
        print(f"\n*** TAINT PROPAGATION ({len(propagated)}) ***")
        propagation_types = {}
        for varnode_id, info in propagated:
            prop_type = info.get('type', 'unknown')
            if prop_type not in propagation_types:
                propagation_types[prop_type] = 0
            propagation_types[prop_type] += 1
        
        for prop_type, count in propagation_types.items():
            print(f"  {prop_type}: {count} instances")
        
        # Print taint paths
        if self.taint_paths:
            print(f"\n*** TAINT PROPAGATION PATHS ({len(self.taint_paths)}) ***")
            for i, path in enumerate(self.taint_paths[:15]):  # Show first 15 paths
                print(f"  {i+1}. {path}")
            if len(self.taint_paths) > 15:
                print(f"  ... and {len(self.taint_paths) - 15} more paths")
        
        # Summary statistics
        print(f"\n*** STATISTICS ***")
        print(f"Total tainted varnodes: {len(self.tainted_varnodes)}")
        print(f"Taint sources: {len(sources)}")
        print(f"Vulnerabilities: {len(vulnerabilities)}")
        print(f"Propagation instances: {len(propagated)}")
        print(f"Propagation paths tracked: {len(self.taint_paths)}")
        print(f"Highlighted addresses: {len(self.highlighted_addresses)}")
        
        # Color legend
        print(f"\n*** HIGHLIGHT COLOR LEGEND ***")
        print("  Light Red: Taint sources (parameters, globals, return values)")
        print("  Light Orange: Tainted data propagation")
        print("  Light Blue: Taint sinks")
        print("  Bright Red: Vulnerabilities (tainted data reaching dangerous operations)")
        print("  Light Purple: Other taint paths")

# Main execution
print("Starting Comprehensive Interactive Taint Analysis with Highlighting...")

if not program:
    print("No program loaded!")
elif not location:
    JOptionPane.showMessageDialog(None,
        "No location selected. Please position cursor in a function.",
        "Error", JOptionPane.ERROR_MESSAGE)
else:
    analyzer = ComprehensiveTaintAnalyzer()
    success = analyzer.analyze_current_function()
    
    if success:
        analyzer.print_comprehensive_summary()
        print("\n=== Analysis Complete ===")
        print("*** Check bookmarks and highlighted code for critical vulnerabilities! ***")
        print("*** Use the decompiler view to see color-coded taint flow! ***")
    else:
        print("Analysis cancelled or failed.")