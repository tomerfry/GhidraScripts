# AST Pattern Query Engine for Ghidra Decompiler - Tree-sitter Style
#@author Tomer Goldschmidt
#@category _NEW_
#@keybinding ctrl shift Q
#@menupath Tools.Analysis.AST Pattern Query
#@toolbar 
#@runtime PyGhidra

from ghidra.app.decompiler import *
from ghidra.program.model.listing import Function
from java.awt import Color, BorderLayout, FlowLayout, Dimension
from javax.swing import *
from javax.swing.table import DefaultTableModel
import re
import json
from collections import defaultdict

class ASTNode:
    """Wrapper for Ghidra tokens to provide uniform interface"""
    def __init__(self, token, parent=None):
        self.token = token
        self.parent = parent
        self.children = []
        self.type = self._determine_type()
        self.text = token.getText() if hasattr(token, 'getText') else ""
        self.address = token.getMinAddress() if hasattr(token, 'getMinAddress') else None
    
    def _determine_type(self):
        """Determine node type from token class"""
        class_name = self.token.__class__.__name__
        
        # Map Ghidra token types to logical types
        if isinstance(self.token, ClangFuncNameToken):
            return 'function_name'
        elif isinstance(self.token, ClangVariableToken):
            return 'variable'
        elif isinstance(self.token, ClangOpToken):
            return 'operator'
        elif isinstance(self.token, ClangSyntaxToken):
            syntax = self.token.getText()
            if syntax in ['if', 'while', 'for', 'switch', 'do']:
                return 'control_flow'
            elif syntax == '(':
                return 'lparen'
            elif syntax == ')':
                return 'rparen'
            elif syntax == ',':
                return 'comma'
            elif syntax == ';':
                return 'semicolon'
            return 'syntax'
        elif isinstance(self.token, ClangTypeToken):
            return 'type'
        elif isinstance(self.token, ClangFieldToken):
            return 'field'
        elif isinstance(self.token, ClangLabelToken):
            return 'label'
        elif isinstance(self.token, ClangCommentToken):
            return 'comment'
        elif 'Const' in class_name:
            return 'constant'
        else:
            return class_name.replace('Clang', '').replace('Token', '').lower()

class Pattern:
    """Represents a compiled query pattern"""
    
    def __init__(self, pattern_str):
        self.raw = pattern_str
        self.type = None
        self.constraints = {}
        self.captures = {}
        self.children = []
        self.parent = None
        self.optional = False
        self.wildcard = False
        self.negated = False
        
    def matches(self, node, captures=None):
        """Check if this pattern matches the given node"""
        if captures is None:
            captures = {}
            
        # Handle wildcards
        if self.wildcard:
            return True
            
        # Handle negation
        if self.negated:
            return not self._match_impl(node, captures)
            
        return self._match_impl(node, captures)
    
    def _match_impl(self, node, captures):
        """Implementation of pattern matching"""
        # Type matching
        if self.type and node.type != self.type:
            return False
            
        # Text matching
        if 'text' in self.constraints:
            pattern_text = self.constraints['text']
            if pattern_text.startswith('$'):
                # Capture
                cap_name = pattern_text[1:]
                if cap_name in captures:
                    if captures[cap_name] != node.text:
                        return False
                else:
                    captures[cap_name] = node.text
            elif pattern_text != '_':
                # Literal or regex match
                if not self._matches_text(pattern_text, node.text):
                    return False
        
        # Match children if specified
        if self.children:
            if not self._match_children(node, captures):
                return False
                
        return True
    
    def _matches_text(self, pattern, text):
        """Check if text matches pattern (supports wildcards)"""
        if pattern == text:
            return True
        
        # Convert wildcards to regex
        if '*' in pattern or '..' in pattern:
            regex = pattern.replace('*', r'[a-zA-Z0-9_]*').replace('..', r'.*')
            regex = '^' + regex + '$'
            return bool(re.match(regex, text))
            
        return False
    
    def _match_children(self, node, captures):
        """Match child patterns against node's children"""
        # This would need more sophisticated matching for sequences, alternatives, etc.
        # For now, simple ordered matching
        if len(self.children) > len(node.children):
            return False
            
        for pattern_child, node_child in zip(self.children, node.children):
            if not pattern_child.matches(node_child, captures):
                return False
                
        return True

class QueryCompiler:
    """Compiles query strings into Pattern objects"""
    
    def __init__(self):
        self.tokens = []
        self.pos = 0
        
    def compile(self, query_str):
        """Compile a query string into a Pattern tree"""
        self.tokens = self._tokenize(query_str)
        self.pos = 0
        return self._parse_pattern()
    
    def _tokenize(self, query_str):
        """Tokenize the query string"""
        # Simple tokenizer - can be enhanced
        tokens = []
        current = ""
        in_string = False
        
        i = 0
        while i < len(query_str):
            char = query_str[i]
            
            if char == '"' and (i == 0 or query_str[i-1] != '\\'):
                in_string = not in_string
                if current:
                    tokens.append(current)
                    current = ""
            elif in_string:
                current += char
            elif char in '()[]{}':
                if current:
                    tokens.append(current)
                    current = ""
                tokens.append(char)
            elif char in ' \t\n':
                if current:
                    tokens.append(current)
                    current = ""
            elif char == ',' or char == ';':
                if current:
                    tokens.append(current)
                    current = ""
                tokens.append(char)
            else:
                current += char
            
            i += 1
        
        if current:
            tokens.append(current)
            
        return tokens
    
    def _parse_pattern(self):
        """Parse a pattern from tokens"""
        if self.pos >= len(self.tokens):
            return None
            
        token = self.tokens[self.pos]
        
        # Handle special tokens
        if token == '_':
            self.pos += 1
            pattern = Pattern('_')
            pattern.wildcard = True
            return pattern
        
        if token == 'NOT':
            self.pos += 1
            pattern = self._parse_pattern()
            if pattern:
                pattern.negated = True
            return pattern
        
        # Handle function calls
        if self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1] == '(':
            return self._parse_function_call()
        
        # Handle operators
        if token in ['=', '==', '!=', '<', '>', '<=', '>=', '+', '-', '*', '/', '%', '&&', '||', '<<', '>>', '&', '|', '^']:
            return self._parse_operator()
        
        # Handle control flow
        if token in ['if', 'while', 'for', 'switch', 'do']:
            return self._parse_control_flow()
        
        # Default: variable or identifier
        pattern = Pattern(token)
        if token.startswith('$'):
            pattern.type = 'variable'
            pattern.constraints['text'] = token
        else:
            pattern.constraints['text'] = token
        
        self.pos += 1
        return pattern
    
    def _parse_function_call(self):
        """Parse a function call pattern"""
        func_name = self.tokens[self.pos]
        self.pos += 1  # Skip function name
        self.pos += 1  # Skip '('
        
        pattern = Pattern(func_name + '(...)')
        pattern.type = 'function_call'
        pattern.constraints['function'] = func_name
        
        # Parse arguments
        args = []
        while self.pos < len(self.tokens) and self.tokens[self.pos] != ')':
            if self.tokens[self.pos] == ',':
                self.pos += 1
                continue
            
            arg_pattern = self._parse_pattern()
            if arg_pattern:
                args.append(arg_pattern)
        
        pattern.constraints['arguments'] = args
        
        if self.pos < len(self.tokens) and self.tokens[self.pos] == ')':
            self.pos += 1
        
        return pattern
    
    def _parse_operator(self):
        """Parse an operator pattern"""
        op = self.tokens[self.pos]
        self.pos += 1
        
        pattern = Pattern(op)
        pattern.type = 'operator'
        pattern.constraints['operator'] = op
        
        # For binary operators, we'd parse left and right operands
        # This is simplified for now
        
        return pattern
    
    def _parse_control_flow(self):
        """Parse a control flow pattern"""
        keyword = self.tokens[self.pos]
        self.pos += 1
        
        pattern = Pattern(keyword)
        pattern.type = 'control_flow'
        pattern.constraints['keyword'] = keyword
        
        # Parse condition if present
        if self.pos < len(self.tokens) and self.tokens[self.pos] == '(':
            self.pos += 1
            condition = self._parse_pattern()
            pattern.constraints['condition'] = condition
            
            if self.pos < len(self.tokens) and self.tokens[self.pos] == ')':
                self.pos += 1
        
        return pattern

class ASTQueryEngine:
    """Main query engine using Tree-sitter-like approach"""
    
    def __init__(self):
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(currentProgram)
        self.ast_cache = {}
        self.debug = False
        
    def __del__(self):
        if hasattr(self, 'decompiler'):
            self.decompiler.dispose()
    
    def build_ast(self, func_entry_point, function_c_markup):
        """Get or cache the AST for a function"""
        func_addr = func_entry_point
        
        if func_addr not in self.ast_cache:
            self.ast_cache[func_addr] = function_c_markup
        
        return self.ast_cache[func_addr]
    
    def _build_ast_from_markup(self, markup):
        """Convert Ghidra markup to our AST representation"""
        root = ASTNode(markup)
        stack = [(root, markup)]
        
        while stack:
            node, ghidra_node = stack.pop()
            
            # Use the tokenIterator to traverse
            for token in ghidra_node.tokenIterator(True):
                child = ASTNode(token, node)
                node.children.append(child)
                
                # If token has children, add to stack for processing
                if hasattr(token, 'tokenIterator'):
                    stack.append((child, token))
        
        return root
    
    def query(self, pattern_str, func=None):
        """Execute a query against the AST"""
        # Compile the pattern
        compiler = QueryCompiler()
        pattern = compiler.compile(pattern_str)
        
        if not pattern:
            print("Failed to compile pattern")
            return []
        
        # Get the function to search
        if func is None:
            func = currentLocation.decompile.function
        
        if not func:
            print("No function found")
            return []
        
        # Build AST
        ast = self.build_ast(func.getEntryPoint(), currentLocation.getDecompile().cCodeMarkup)
        if not ast:
            print("Failed to build AST")
            return []
        ast = self._build_ast_from_markup(ast)  # Convert to our ASTNode structure
        # Search the AST

        results = []
        captures = {}
        self._search_ast(ast, pattern, results, captures, func.getName())
        
        return results, captures
    
    def _search_ast(self, node, pattern, results, captures, func_name):
        """Recursively search the AST for pattern matches"""
        # Try to match at this node
        local_captures = dict(captures)
        print(pattern.raw, node.type, node.text)
        if pattern.matches(node, local_captures):
            # Found a match
            result = {
                'node': node,
                'type': node.type,
                'text': node.text,
                'address': node.address,
                'function': func_name,
                'captures': dict(local_captures)
            }
            results.append(result)
            
            # Update global captures
            captures.update(local_captures)
        
        # Recursively search children
        for child in node.children:
            self._search_ast(child, pattern, results, captures, func_name)
    
    def query_all_functions(self, pattern_str):
        """Execute a query against all functions"""
        all_results = []
        all_captures = {}
        
        fm = currentProgram.getFunctionManager()
        for func in fm.getFunctions(True):
            results, captures = self.query(pattern_str, func)
            all_results.extend(results)
            all_captures.update(captures)
        
        return all_results, all_captures

class AdvancedQueryCompiler(QueryCompiler):
    """Enhanced query compiler with more features"""
    
    def compile(self, query_str):
        """Compile complex queries with multiple patterns"""
        # Handle complex queries like: "malloc($size) && NOT free(_)"
        if '&&' in query_str:
            parts = query_str.split('&&')
            patterns = [super().compile(part.strip()) for part in parts]
            return ('and', patterns)
        elif '||' in query_str:
            parts = query_str.split('||')
            patterns = [super().compile(part.strip()) for part in parts]
            return ('or', patterns)
        else:
            return super().compile(query_str)

class ASTQueryPanel:
    """GUI panel for AST queries"""
    
    def __init__(self, engine):
        self.engine = engine
        self.results = []
        self.panel = JPanel(BorderLayout())
        self._init_ui()
    
    def _init_ui(self):
        # Top panel with query input
        top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        # Query input field
        self.query_field = JTextField(50)
        self.query_field.setToolTipText("Enter pattern query")
        
        # Search button
        search_btn = JButton("Search Current")
        search_btn.addActionListener(lambda e: self._run_query(False))
        
        # Search all button
        search_all_btn = JButton("Search All")
        search_all_btn.addActionListener(lambda e: self._run_query(True))
        
        # Clear button
        clear_btn = JButton("Clear")
        clear_btn.addActionListener(lambda e: self._clear_results())
        
        top_panel.add(JLabel("Query:"))
        top_panel.add(self.query_field)
        top_panel.add(search_btn)
        top_panel.add(search_all_btn)
        top_panel.add(clear_btn)
        
        # Help text
        help_text = JTextArea(3, 60)
        help_text.setText(
            "Query Syntax Examples:\n" +
            "  strcmp($a, $b)  - Find strcmp calls, capture arguments\n" +
            "  buffer* = _     - Find assignments to variables starting with 'buffer'\n" +
            "  if ($cond)      - Find if statements, capture condition\n" +
            "  NOT free(_)     - Find code without free calls"
        )
        help_text.setEditable(False)
        help_text.setBackground(self.panel.getBackground())
        
        # Query panel wrapper
        query_wrapper = JPanel(BorderLayout())
        query_wrapper.add(top_panel, BorderLayout.NORTH)
        query_wrapper.add(help_text, BorderLayout.SOUTH)
        
        # Results table
        self.table_model = DefaultTableModel()
        self.table_model.addColumn("#")
        self.table_model.addColumn("Function")
        self.table_model.addColumn("Type")
        self.table_model.addColumn("Match")
        self.table_model.addColumn("Address")
        
        self.results_table = JTable(self.table_model)
        self.results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.results_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_row_selected(e) if not e.getValueIsAdjusting() else None
        )
        
        # Set column widths
        self.results_table.getColumnModel().getColumn(0).setPreferredWidth(40)
        self.results_table.getColumnModel().getColumn(1).setPreferredWidth(120)
        self.results_table.getColumnModel().getColumn(2).setPreferredWidth(100)
        self.results_table.getColumnModel().getColumn(3).setPreferredWidth(300)
        self.results_table.getColumnModel().getColumn(4).setPreferredWidth(100)
        
        scroll_pane = JScrollPane(self.results_table)
        scroll_pane.setPreferredSize(Dimension(700, 400))
        
        # Bottom panel
        bottom_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        
        self.status_label = JLabel("Ready")
        self.captures_label = JLabel("")
        
        goto_btn = JButton("Go to Address")
        goto_btn.addActionListener(lambda e: self._goto_selected())
        
        bottom_panel.add(self.status_label)
        bottom_panel.add(Box.createHorizontalStrut(20))
        bottom_panel.add(self.captures_label)
        bottom_panel.add(Box.createHorizontalStrut(20))
        bottom_panel.add(goto_btn)
        
        # Add components to main panel
        self.panel.add(query_wrapper, BorderLayout.NORTH)
        self.panel.add(scroll_pane, BorderLayout.CENTER)
        self.panel.add(bottom_panel, BorderLayout.SOUTH)
        
        # Enable Enter key for search
        self.query_field.addActionListener(lambda e: self._run_query(False))
    
    def getPanel(self):
        return self.panel
    
    def _run_query(self, search_all):
        """Execute the query"""
        query = self.query_field.getText().strip()
        if not query:
            return
        
        self.status_label.setText("Searching...")
        self.table_model.setRowCount(0)
        
        try:
            if search_all:
                results, captures = self.engine.query_all_functions(query)
            else:
                results, captures = self.engine.query(query)
            
            self.results = results
            
            # Display captures
            if captures:
                cap_text = "Captures: " + ", ".join(["{}={}".format(k, v) for k, v in captures.items()])
                self.captures_label.setText(cap_text[:50] + "..." if len(cap_text) > 50 else cap_text)
            else:
                self.captures_label.setText("")
            
            # Populate table
            for i, result in enumerate(results):
                row_data = [
                    i + 1,
                    result['function'],
                    result['type'],
                    result['text'][:50] + "..." if len(result['text']) > 50 else result['text'],
                    str(result['address']) if result['address'] else "N/A"
                ]
                self.table_model.addRow(row_data)
            
            self.status_label.setText("Found {} matches".format(len(results)))
            
        except Exception as e:
            self.status_label.setText("Error: {}".format(str(e)))
            print("Query error: {}".format(e))
            import traceback
            traceback.print_exc()
    
    def _clear_results(self):
        """Clear all results"""
        self.table_model.setRowCount(0)
        self.results = []
        self.status_label.setText("Cleared")
        self.captures_label.setText("")
        self.query_field.setText("")
    
    def _on_row_selected(self, event):
        """Handle row selection"""
        row = self.results_table.getSelectedRow()
        if row >= 0 and row < len(self.results):
            result = self.results[row]
            if result['address']:
                goTo(result['address'])
    
    def _goto_selected(self):
        """Go to selected result address"""
        row = self.results_table.getSelectedRow()
        if row >= 0 and row < len(self.results):
            result = self.results[row]
            if result['address']:
                goTo(result['address'])

def show_query_window():
    """Show the query window"""
    frame = JFrame("AST Pattern Query Engine")
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    
    engine = ASTQueryEngine()
    query_panel = ASTQueryPanel(engine)
    
    frame.add(query_panel.getPanel())
    frame.setSize(800, 600)
    frame.setLocationRelativeTo(None)
    frame.setVisible(True)

# Run the GUI
show_query_window()