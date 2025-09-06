# Variable Assignment of TG_ vars with Force Re-decompile Toggle
#@author Tomer Goldschmidt
#@category _NEW_
#@keybinding ctrl shift T
#@menupath Tools.Highlighters.Toggle TG_ Variables
#@toolbar 
#@runtime PyGhidra

from ghidra.app.decompiler import *
from java.awt import Color
import jpype
from jpype import JImplements, JOverride

HIGHLIGHTER_ID = "TG_Variable_Highlighter_v3"

# Store state in tool options for persistence
def get_persistent_state(tool):
    """Get the persistent toggle state from tool options"""
    options = tool.getOptions("TG_Highlighter")
    return options.getBoolean("enabled", False)

def set_persistent_state(tool, enabled):
    """Set the persistent toggle state in tool options"""
    options = tool.getOptions("TG_Highlighter")
    options.setBoolean("enabled", enabled)

@JImplements(CTokenHighlightMatcher)
class TGHighlightMatcher:
    """Token highlighter for TG_ variables"""
    
    def __init__(self, enabled=True):
        self.assignment_color = Color(255, 255, 200)  # Light yellow
        self.declaration_color = Color(200, 255, 200)  # Light green
        self.statement_color = Color(240, 240, 240)  # Very light gray
        self.tokens_to_highlight = {}
        self.enabled = enabled
    
    @JOverride
    def start(self, root):
        self.tokens_to_highlight.clear()
        if self.enabled:
            self.analyze_node(root)
    
    @JOverride
    def getTokenHighlight(self, token):
        if not self.enabled:
            return None
        return self.tokens_to_highlight.get(token, None)
    
    @JOverride
    def end(self):
        pass
    
    def analyze_node(self, node):
        if isinstance(node, ClangToken):
            self.check_for_tg_pattern(node)
        
        for i in range(node.numChildren()):
            self.analyze_node(node.Child(i))
    
    def check_for_tg_pattern(self, token):
        if isinstance(token, ClangVariableToken):
            var_name = token.getText()
            if var_name.startswith("TG_"):
                if self.is_assignment(token):
                    self.tokens_to_highlight[token] = self.assignment_color
                    self.highlight_statement(token)
                elif self.is_declaration(token):
                    self.tokens_to_highlight[token] = self.declaration_color
    
    def is_assignment(self, var_token):
        parent = var_token.Parent()
        if not parent:
            return False
            
        found_var = False
        for i in range(parent.numChildren()):
            child = parent.Child(i)
            if child == var_token:
                found_var = True
            elif found_var and isinstance(child, ClangOpToken):
                op_text = child.getText()
                if op_text in ["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="]:
                    return True
                elif op_text not in [" ", "\t", "\n"]:
                    return False
        return False
    
    def is_declaration(self, var_token):
        parent = var_token.Parent()
        if isinstance(parent, ClangVariableDecl):
            return True
        
        if parent:
            found_type = False
            for i in range(parent.numChildren()):
                child = parent.Child(i)
                if isinstance(child, ClangTypeToken):
                    found_type = True
                elif child == var_token and found_type:
                    return True
        return False
    
    def highlight_statement(self, var_token):
        parent = var_token.Parent()
        if parent:
            for i in range(parent.numChildren()):
                child = parent.Child(i)
                if isinstance(child, ClangToken) and child not in self.tokens_to_highlight:
                    self.tokens_to_highlight[child] = self.statement_color

def force_redecompile(tool):
    """Force re-decompilation of current function to apply highlighting changes"""
    
    # Get current function
    func = getFunctionContaining(currentAddress)
    if not func:
        return False
    
    try:
        from ghidra.app.plugin.core.decompile import DecompilerProvider
        
        # Create a fresh decompiler
        decompiler = DecompInterface()
        decompiler.openProgram(currentProgram)
        
        # Re-decompile the function
        results = decompiler.decompileFunction(func, 30, monitor)
        
        if results.decompileCompleted():
            # Push the new decompilation to all decompiler windows
            providers = tool.getWindowManager().getComponentProviders(DecompilerProvider)
            
            for provider in providers:
                try:
                    # Set the new decompilation data
                    provider.setDecompileData(results)
                    return True
                except:
                    pass
        
        decompiler.dispose()
        
    except Exception as e:
        print(f"Re-decompile error: {e}")
    
    return False

def toggle_highlighter():
    """Toggle the TG_ highlighter with forced re-decompilation"""
    
    tool = state.getTool()
    service = tool.getService(DecompilerHighlightService)
    
    if not service:
        print("ERROR: DecompilerHighlightService not available")
        print("Make sure the Decompiler window is open")
        return
    
    # Get current state and toggle it
    current_state = get_persistent_state(tool)
    new_state = not current_state
    
    # Save the new state
    set_persistent_state(tool, new_state)
    
    # Create matcher with new state
    matcher = TGHighlightMatcher(enabled=new_state)
    
    # Create/update the highlighter
    service.createHighlighter(HIGHLIGHTER_ID, matcher)
    
    # Print status
    print("\n" + "=" * 50)
    if new_state:
        print("✓ TG_ Highlighter: ON")
        print("=" * 50)
        print("Highlighting patterns:")
        print("  • Yellow: TG_ variable assignments")
        print("  • Green: TG_ variable declarations")
        print("  • Light gray: Associated tokens")
    else:
        print("✗ TG_ Highlighter: OFF")
        print("=" * 50)
        print("All highlights removed")
    
    # Force re-decompilation for immediate effect
    print("\nRe-decompiling current function...")
    
    if force_redecompile(tool):
        print("✓ Re-decompilation complete - highlights updated!")
    else:
        print("⚠ Could not auto re-decompile")
        print("  Press 'F5' in the decompiler to refresh manually")
    
    print(f"\nPress Ctrl+T to toggle {'OFF' if new_state else 'ON'}")

# Run the toggle
toggle_highlighter()