# AST Pattern Query Engine for Ghidra Decompiler
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

class QueryParser:
    """Parse weggli-like query strings into a structured format"""
    
    def __init__(self):
        self.pattern = None
        self.type = None
        self.constraints = {}

    def parse(self, query):
        """Parse a query string and return a structured representation"""
        query = query.strip()
        
        # Function call: func(args) or func(_)
        if '(' in query and ')' in query:
            self.type = 'function_call'
            func_part = query[:query.index('(')]
            args_part = query[query.index('(')+1:query.rindex(')')]
            func_name = func_part.strip()
            
            # Parse arguments - can be captures like $a, wildcards _, or literals
            args = []
            if args_part.strip():
                args = [arg.strip() for arg in args_part.split(',')]
            
            self.constraints['func_pattern'] = self._convert_to_regex(func_name)
            self.constraints['args'] = args  # Keep original for capture support
            return self
        
        # Control flow: if expr, while expr, etc. (without parentheses in query)
        elif any(query.startswith(kw + ' ') for kw in ['if', 'while', 'for', 'switch']):
            self.type = 'control_flow'
            parts = query.split(' ', 1)
            self.constraints['flow_type'] = parts[0]
            if len(parts) > 1:
                condition = parts[1].strip()
                self.constraints['condition_pattern'] = self._convert_to_regex(condition) if condition != '_' else None
            return self
        
        # Assignment: var = expr
        elif '=' in query and not any(op in query for op in ['==', '!=', '<=', '>=']):
            self.type = 'assignment'
            var, expr = query.split('=', 1)
            var = var.strip()
            expr = expr.strip()
            self.constraints['var_pattern'] = self._convert_to_regex(var)
            self.constraints['value_pattern'] = self._convert_to_regex(expr) if expr != '_' else None
            return self
        
        # Binary operators
        elif any(op in query for op in ['&&', '||', '<<', '>>', '<=', '>=', '==', '!=', '+', '-', '*', '/', '%', '&', '|', '^', '<', '>']):
            self.type = 'operator'
            # Sort operators by length to match longer ones first
            for op in ['&&', '||', '<<', '>>', '<=', '>=', '==', '!=', '+', '-', '*', '/', '%', '&', '|', '^', '<', '>']:
                if op in query:
                    parts = query.split(op, 1)
                    self.constraints['operator'] = op
                    self.constraints['op_type'] = self._map_operator_to_category(op)
                    left = parts[0].strip() if len(parts) > 0 else '_'
                    right = parts[1].strip() if len(parts) > 1 else '_'
                    self.constraints['left_pattern'] = self._convert_to_regex(left) if left != '_' else None
                    self.constraints['right_pattern'] = self._convert_to_regex(right) if right != '_' else None
                    break
            return self
        
        # Unary operators
        elif any(query.startswith(op) for op in ['!', '~', '-', '*', '&']):
            self.type = 'operator'
            for op in ['!', '~', '-', '*', '&']:
                if query.startswith(op):
                    self.constraints['operator'] = op
                    self.constraints['op_type'] = self._map_operator_to_category(op)
                    operand = query[len(op):].strip()
                    self.constraints['operand_pattern'] = self._convert_to_regex(operand) if operand != '_' else None
                    self.constraints['unary'] = True
                    break
            return self
        
        # Variable or identifier
        else:
            self.type = 'variable'
            self.constraints['var_pattern'] = self._convert_to_regex(query)
            return self
    
    def _convert_to_regex(self, pattern):
        """Convert weggli-like pattern to regex"""
        if pattern == '_':
            return '.*'  # Match anything
        if pattern.startswith('$'):
            # Capture variable - we'll handle this specially
            return pattern
        # Handle weggli wildcards
        pattern = re.escape(pattern)
        pattern = pattern.replace(r'\*', r'[a-zA-Z0-9_]*')  # * matches identifier chars
        pattern = pattern.replace(r'\.\.', r'.*')  # .. matches anything
        return pattern
    
    def _map_operator_to_category(self, op):
        """Map operator to category"""
        op_categories = {
            '+': 'arithmetic', '-': 'arithmetic', '*': 'arithmetic', '/': 'arithmetic', '%': 'arithmetic',
            '&': 'bitwise', '|': 'bitwise', '^': 'bitwise', '~': 'bitwise', '<<': 'bitwise', '>>': 'bitwise',
            '==': 'comparison', '!=': 'comparison', '<': 'comparison', '>': 'comparison', '<=': 'comparison', '>=': 'comparison',
            '&&': 'logical', '||': 'logical', '!': 'logical',
            '*_ptr': 'pointer', '&_ptr': 'pointer'  # For pointer dereference and address-of
        }
        return op_categories.get(op, 'unknown')

class ASTPatternEngine:
    """
    Incremental parsing and querying engine for decompiled code AST
    """
    
    def __init__(self):
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(currentProgram)
        self.ast_cache = {}  # Cache decompiled ASTs
        self.results = []
        self.captures = {}  # Store captured variables
        self.debug = True  # Enable debug output
        
    def __del__(self):
        if hasattr(self, 'decompiler'):
            self.decompiler.dispose()
    
    def get_ast(self, func_entry_point, function_c_markup):
        """Get or cache the AST for a function"""
        func_addr = func_entry_point
        
        if func_addr not in self.ast_cache:
            self.ast_cache[func_addr] = function_c_markup
                
        return self.ast_cache[func_addr]
    
    def clear_cache(self):
        """Clear the AST cache"""
        self.ast_cache.clear()
    
    def traverse_ast(self, node, callback, depth=0, parent=None):
        """
        Traverse AST and call callback for each node
        callback(node, depth, parent) -> bool (True to continue traversing children)
        """
        if not node:
            return
            
        continue_traversal = callback(node, depth, parent)
        
        if continue_traversal:
            for i in range(node.numChildren()):
                child = node.Child(i)
                self.traverse_ast(child, callback, depth + 1, node)
    
    def find_pattern(self, pattern_type, **kwargs):
        """
        Find patterns in the AST based on parsed query - searches all functions
        """
        self.results = []
        self.captures = {}  # Reset captures for each search
        
        if self.debug:
            print("\n=== Starting pattern search ===")
            print("Pattern type: {}".format(pattern_type))
            print("Constraints: {}".format(kwargs))
        
        func = currentLocation.decompile.function
        
        ast = self.get_ast(func.getEntryPoint(), currentLocation.getDecompile().cCodeMarkup)
        if ast:
            self.current_function = func

            self.traverse_ast(ast, lambda a,b,c: print(a,b,c))
            if pattern_type == 'assignment':
                self._find_assignments_in_ast(ast, **kwargs)
            elif pattern_type == 'function_call':
                self._find_function_calls_in_ast(ast, **kwargs)
            elif pattern_type == 'variable':
                self._find_variables_in_ast(ast, **kwargs)
            elif pattern_type == 'operator':
                self._find_operators_in_ast(ast, **kwargs)
            elif pattern_type == 'control_flow':
                self._find_control_flow_in_ast(ast, **kwargs)
        
        if self.debug:
            print("Total results found: {}".format(len(self.results)))
            print("=== Search complete ===\n")
        
        return self.results
    
    def _find_assignments_in_ast(self, ast, var_pattern=None, value_pattern=None, operator=None):
        """Find assignment operations in given AST"""
        def check_assignment(node, depth, parent):
            if isinstance(node, ClangOpToken):
                op_text = node.getText()
                
                assignment_ops = ["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="]
                if operator:
                    assignment_ops = [operator]
                
                if op_text in assignment_ops:
                    if parent:
                        var_found = None
                        for i in range(parent.numChildren()):
                            child = parent.Child(i)
                            if child == node:
                                break
                            if isinstance(child, ClangVariableToken):
                                var_found = child
                        
                        if var_found:
                            var_name = var_found.getText()
                            
                            if var_pattern and not re.match(var_pattern, var_name):
                                return True
                            
                            value_text = self._get_expression_after(parent, node)
                            
                            if value_pattern and value_text and not re.match(value_pattern, value_text):
                                return True
                            
                            self.results.append({
                                'type': 'assignment',
                                'variable': var_name,
                                'operator': op_text,
                                'value': value_text,
                                'node': node,
                                'parent': parent,
                                'address': node.getMinAddress(),
                                'function': self.current_function.getName()
                            })
            
            return True
        
        self.traverse_ast(ast, check_assignment)
    
    def _find_function_calls_in_ast(self, ast, func_pattern=None, args=None, **kwargs):
        """Find function calls in given AST"""
        if self.debug:
            print("  Looking for function calls with pattern: {}, args: {}".format(func_pattern, args))
        
        def check_function_call(node, depth, parent):
            # Look for function calls in the AST structure
            if isinstance(node, ClangFuncNameToken):
                func_name = node.getText()
                
                if self.debug and (func_name == "strlen" or "str" in func_name):
                    print("    Found function token: {} at depth {}".format(func_name, depth))
                    print("    Node class: {}".format(node.__class__.__name__))
                    if parent:
                        print("    Parent class: {}".format(parent.__class__.__name__))
                
                # Check function name pattern
                if func_pattern:
                    if func_pattern.startswith('$'):
                        # Capture function name
                        self.captures[func_pattern] = func_name
                    else:
                        match_result = re.match(func_pattern, func_name)
                        if self.debug and func_name == "strlen":
                            print("    Pattern match '{}' against '{}': {}".format(func_pattern, func_name, match_result))
                        if not match_result:
                            return True
                
                # Try multiple methods to get arguments
                extracted_args = []
                
                # Method 1: Get statement node
                statement_node = self._get_statement_node(node)
                if statement_node:
                    extracted_args = self._extract_function_arguments(statement_node, node)
                    if self.debug and func_name == "strlen":
                        print("    Method 1 - Statement args: {}".format(extracted_args))
                
                # Method 2: Try direct parent traversal if method 1 fails
                if not extracted_args and parent:
                    extracted_args = self._extract_args_from_parent(parent, node)
                    if self.debug and func_name == "strlen":
                        print("    Method 2 - Parent args: {}".format(extracted_args))
                
                # Match arguments if specified
                if args is not None:
                    if not self._match_arguments(args, extracted_args):
                        if self.debug and func_name == "strlen":
                            print("    Argument match failed")
                        return True
                
                if self.debug and func_name == "strlen":
                    print("    MATCH FOUND!")
                
                self.results.append({
                    'type': 'function_call',
                    'function': func_name,
                    'arguments': extracted_args,
                    'node': node,
                    'parent': parent,
                    'address': node.getMinAddress(),
                    'containing_function': self.current_function.getName()
                })
            
            return True
        
        self.traverse_ast(ast, check_function_call)
    
    def _extract_args_from_parent(self, parent, func_node):
        """Alternative method to extract arguments by examining parent structure"""
        args = []
        tokens = []
        
        # Collect tokens from parent
        for i in range(parent.numChildren()):
            child = parent.Child(i)
            if isinstance(child, ClangToken):
                tokens.append(child)
            else:
                # Recursively collect from non-token children
                self._collect_tokens(child, tokens)
        
        # Find function position
        func_index = -1
        for i, token in enumerate(tokens):
            if token == func_node:
                func_index = i
                break
        
        if func_index == -1 or func_index >= len(tokens) - 1:
            return args
        
        # Look for arguments after function name
        paren_depth = 0
        in_args = False
        current_arg = []
        
        for i in range(func_index + 1, len(tokens)):
            token = tokens[i]
            text = token.getText() if hasattr(token, 'getText') else ''
            
            if text == '(' and not in_args:
                in_args = True
                paren_depth = 1
            elif in_args:
                if text == '(':
                    paren_depth += 1
                    current_arg.append(text)
                elif text == ')':
                    paren_depth -= 1
                    if paren_depth == 0:
                        if current_arg:
                            args.append(''.join(current_arg))
                        break
                    else:
                        current_arg.append(text)
                elif text == ',' and paren_depth == 1:
                    if current_arg:
                        args.append(''.join(current_arg))
                        current_arg = []
                else:
                    current_arg.append(text)
        
        return args
    
    def _get_statement_node(self, node):
        """Find the containing statement node"""
        current = node
        depth = 0
        while current and depth < 10:  # Prevent infinite loops
            parent = current.Parent() if hasattr(current, 'Parent') else None
            if not parent:
                if self.debug:
                    print("      No parent found at depth {}".format(depth))
                break
            
            if self.debug and hasattr(current, 'getText') and current.getText() == "strlen":
                print("      Traversing up: {} -> {}".format(
                    current.__class__.__name__, 
                    parent.__class__.__name__ if parent else "None"
                ))
            
            # Check various statement types
            parent_class_name = parent.__class__.__name__
            if any(stmt in parent_class_name for stmt in ['Statement', 'ClangStatement', 'ClangTokenGroup']):
                if self.debug:
                    print("      Found statement node: {}".format(parent_class_name))
                return parent
            
            current = parent
            depth += 1
        
        # If no statement found, return the highest parent we found
        return current if current != node else None
    
    def _collect_tokens(self, node, tokens):
        """Recursively collect all tokens from a node"""
        if node is None:
            return
            
        if isinstance(node, ClangToken):
            tokens.append(node)
            if self.debug and hasattr(node, 'getText') and 'strlen' in node.getText():
                print("        Collected token: {} ({})".format(node.getText(), node.__class__.__name__))
        
        # Always try to traverse children
        try:
            for i in range(node.numChildren()):
                child = node.Child(i)
                self._collect_tokens(child, tokens)
        except:
            # Node might not have children
            pass
    
    def _tokens_to_string(self, tokens):
        """Convert a list of tokens to a string"""
        parts = []
        for token in tokens:
            if hasattr(token, 'getText'):
                parts.append(token.getText())
        return ''.join(parts).strip()
    
    def _match_arguments(self, patterns, actual_args):
        """Match argument patterns against actual arguments"""
        if len(patterns) != len(actual_args):
            return False
        
        for pattern, actual in zip(patterns, actual_args):
            if pattern == '_':
                # Wildcard matches anything
                continue
            elif pattern.startswith('$'):
                # Capture argument
                if pattern in self.captures:
                    # Check if captured value matches
                    if self.captures[pattern] != actual:
                        return False
                else:
                    # First time seeing this capture
                    self.captures[pattern] = actual
            else:
                # Literal match
                if not re.match(self._convert_to_regex(pattern), actual):
                    return False
        
        return True
    
    def _get_function_args(self, parent):
        """Get function arguments as strings"""
        # This method needs to be more sophisticated
        args = []
        if not parent:
            return args
        
        # Find the statement containing the function call
        statement = self._get_statement_node(parent)
        if statement:
            # Extract arguments from the statement structure
            tokens = []
            self._collect_tokens(statement, tokens)
            
            # Find parentheses and extract arguments
            in_parens = False
            paren_depth = 0
            current_arg = []
            
            for token in tokens:
                if isinstance(token, ClangSyntaxToken):
                    text = token.getText()
                    if text == '(':
                        paren_depth += 1
                        if paren_depth == 1:
                            in_parens = True
                        else:
                            current_arg.append(text)
                    elif text == ')':
                        paren_depth -= 1
                        if paren_depth == 0:
                            if current_arg:
                                args.append(''.join(current_arg).strip())
                            break
                        else:
                            current_arg.append(text)
                    elif text == ',' and paren_depth == 1:
                        if current_arg:
                            args.append(''.join(current_arg).strip())
                            current_arg = []
                    elif in_parens:
                        current_arg.append(text)
                elif in_parens and isinstance(token, ClangToken):
                    current_arg.append(token.getText())
        
        return args
    
    def _find_operators_in_ast(self, ast, operator=None, op_type=None, left_pattern=None, right_pattern=None, operand_pattern=None, unary=False):
        """Find operators in given AST"""
        def check_operator(node, depth, parent):
            if isinstance(node, ClangOpToken):
                op_text = node.getText()
                
                if operator and op_text != operator:
                    return True
                
                if op_type:
                    op_categories = {
                        'arithmetic': ['+', '-', '*', '/', '%'],
                        'bitwise': ['&', '|', '^', '~', '<<', '>>'],
                        'comparison': ['==', '!=', '<', '>', '<=', '>='],
                        'logical': ['&&', '||', '!'],
                        'assignment': ['=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>='],
                        'pointer': ['*', '&']
                    }
                    
                    if op_type in op_categories and op_text not in op_categories[op_type]:
                        return True
                
                operands = self._get_operands(node, parent)
                
                # Check patterns
                if unary and operand_pattern and operands:
                    if not re.match(operand_pattern, operands[0]):
                        return True
                elif not unary:
                    if left_pattern and len(operands) > 0:
                        if not re.match(left_pattern, operands[0]):
                            return True
                    if right_pattern and len(operands) > 1:
                        if not re.match(right_pattern, operands[1]):
                            return True
                
                self.results.append({
                    'type': 'operator',
                    'operator': op_text,
                    'operands': operands,
                    'node': node,
                    'parent': parent,
                    'address': node.getMinAddress(),
                    'function': self.current_function.getName()
                })
            
            return True
        
        self.traverse_ast(ast, check_operator)
    
    def _find_variables_in_ast(self, ast, var_pattern=None, context=None):
        """Find variable usage in given AST"""
        def check_variable(node, depth, parent):
            if isinstance(node, ClangVariableToken):
                var_name = node.getText()
                
                if var_pattern and not re.match(var_pattern, var_name):
                    return True
                
                var_context = self._get_variable_context(node, parent)
                
                if context and context != var_context:
                    return True
                
                self.results.append({
                    'type': 'variable',
                    'name': var_name,
                    'context': var_context,
                    'node': node,
                    'parent': parent,
                    'address': node.getMinAddress(),
                    'function': self.current_function.getName()
                })
            
            return True
        
        self.traverse_ast(ast, check_variable)
    
    def _find_control_flow_in_ast(self, ast, flow_type=None, condition_pattern=None):
        """Find control flow structures in given AST"""
        def check_control_flow(node, depth, parent):
            if isinstance(node, ClangSyntaxToken):
                syntax = node.getText()
                
                control_keywords = ['if', 'else', 'while', 'for', 'do', 'switch', 'case', 'return', 'break', 'continue', 'goto']
                
                if syntax in control_keywords:
                    if flow_type and syntax != flow_type:
                        return True
                    
                    condition = self._get_control_condition(node, parent)
                    
                    if condition_pattern and condition and not re.match(condition_pattern, condition):
                        return True
                    
                    self.results.append({
                        'type': 'control_flow',
                        'keyword': syntax,
                        'condition': condition,
                        'node': node,
                        'parent': parent,
                        'address': node.getMinAddress(),
                        'function': self.current_function.getName()
                    })
            
            return True
        
        self.traverse_ast(ast, check_control_flow)
    
    # Helper methods
    def _get_expression_after(self, parent, after_node):
        """Get expression text after a given node"""
        found = False
        parts = []
        
        for i in range(parent.numChildren()):
            child = parent.Child(i)
            if child == after_node:
                found = True
                continue
            if found:
                if isinstance(child, ClangToken):
                    text = child.getText()
                    if text in [';', '\n']:
                        break
                    parts.append(text)
        
        return ''.join(parts).strip()
    
    def _count_function_args(self, parent):
        """Count function arguments"""
        args = []
        in_parens = False
        current_arg = []
        
        for i in range(parent.numChildren()):
            child = parent.Child(i)
            if isinstance(child, ClangSyntaxToken):
                if child.getText() == '(':
                    in_parens = True
                elif child.getText() == ')':
                    if current_arg:
                        args.append(''.join(current_arg).strip())
                    break
                elif child.getText() == ',' and in_parens:
                    if current_arg:
                        args.append(''.join(current_arg).strip())
                        current_arg = []
            elif in_parens and isinstance(child, ClangToken):
                current_arg.append(child.getText())
        
        return args
    
    def _get_variable_context(self, node, parent):
        """Determine variable usage context"""
        if not parent:
            return 'unknown'
        
        for i in range(parent.numChildren()):
            child = parent.Child(i)
            if child == node:
                for j in range(i + 1, parent.numChildren()):
                    next_child = parent.Child(j)
                    if isinstance(next_child, ClangOpToken):
                        if '=' in next_child.getText():
                            return 'assignment_target'
                        break
        
        for i in range(parent.numChildren()):
            if isinstance(parent.Child(i), ClangFuncNameToken):
                return 'function_argument'
        
        if self._is_in_condition(node, parent):
            return 'condition'
        
        return 'read'
    
    def _is_in_condition(self, node, parent):
        """Check if node is within a condition"""
        current = parent
        while current:
            for i in range(current.numChildren()):
                child = current.Child(i)
                if isinstance(child, ClangSyntaxToken):
                    if child.getText() in ['if', 'while', 'for']:
                        return True
            current = current.Parent() if hasattr(current, 'Parent') else None
        return False
    
    def _get_operands(self, op_node, parent):
        """Get operands for an operator"""
        operands = []
        op_index = -1
        
        for i in range(parent.numChildren()):
            if parent.Child(i) == op_node:
                op_index = i
                break
        
        if op_index > 0:
            left = parent.Child(op_index - 1)
            if isinstance(left, ClangToken):
                operands.append(left.getText())
        
        if op_index < parent.numChildren() - 1:
            right = parent.Child(op_index + 1)
            if isinstance(right, ClangToken):
                operands.append(right.getText())
        
        return operands
    
    def _get_control_condition(self, control_node, parent):
        """Extract condition from control flow statement"""
        condition_parts = []
        in_parens = False
        
        for i in range(parent.numChildren()):
            child = parent.Child(i)
            if isinstance(child, ClangSyntaxToken):
                if child.getText() == '(':
                    in_parens = True
                elif child.getText() == ')':
                    break
            elif in_parens and isinstance(child, ClangToken):
                condition_parts.append(child.getText())
        
        return ''.join(condition_parts).strip()

def highlight_results(results):
    """Highlight query results in the decompiler"""
    # For PyGhidra, we need to use the decompiler controller
    from ghidra.app.decompiler import DecompilerHighlightService
    from ghidra.app.plugin.core.decompile import DecompilerProvider
    
    tool = state.getTool()
    
    # Find the decompiler provider
    providers = tool.getComponentProviders()
    decompiler_provider = None
    
    for provider in providers:
        if isinstance(provider, DecompilerProvider):
            decompiler_provider = provider
            break
    
    if decompiler_provider:
        controller = decompiler_provider.getController()
        
        # Clear existing highlights
        highlight_service = controller.getDecompilerPanel().getHighlightService()
        highlight_service.clearPrimaryHighlights()
        
        # Apply new highlights
        for r in results:
            if 'address' in r and r['address']:
                highlight_service.applyPrimaryHighlights(r['address'], Color.CYAN)
        
        print("Results highlighted in cyan in the decompiler")
    else:
        print("Could not find decompiler provider")

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
        self.query_field = JTextField(40)
        self.query_field.setToolTipText("Enter query (e.g., TG_* = _; or strcmp(_,_);)")
        
        # Search button
        search_btn = JButton("Search")
        search_btn.addActionListener(lambda e: self._run_query())
        
        # Clear button
        clear_btn = JButton("Clear")
        clear_btn.addActionListener(lambda e: self._clear_results())
        
        # Example label
        examples_label = JLabel("Examples: strcmp($, _) | $func() | buffer_$ = _ | _ >> $ | if _ ")
        examples_label.setFont(examples_label.getFont().deriveFont(10.0))
        
        top_panel.add(JLabel("Query:"))
        top_panel.add(self.query_field)
        top_panel.add(search_btn)
        top_panel.add(clear_btn)
        
        # Query panel wrapper
        query_wrapper = JPanel(BorderLayout())
        query_wrapper.add(top_panel, BorderLayout.NORTH)
        query_wrapper.add(examples_label, BorderLayout.SOUTH)
        
        # Results table
        self.table_model = DefaultTableModel()
        self.table_model.addColumn("#")
        self.table_model.addColumn("Type")
        self.table_model.addColumn("Match")
        self.table_model.addColumn("Address")
        
        self.results_table = JTable(self.table_model)
        self.results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.results_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_row_selected(e) if not e.getValueIsAdjusting() else None
        )
        
        # Set column widths
        self.results_table.getColumnModel().getColumn(0).setPreferredWidth(30)
        self.results_table.getColumnModel().getColumn(1).setPreferredWidth(80)
        self.results_table.getColumnModel().getColumn(2).setPreferredWidth(400)
        self.results_table.getColumnModel().getColumn(3).setPreferredWidth(100)
        
        scroll_pane = JScrollPane(self.results_table)
        scroll_pane.setPreferredSize(Dimension(600, 400))
        
        # Bottom panel with actions
        bottom_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        
        self.status_label = JLabel("Ready")
        highlight_btn = JButton("Highlight Results")
        highlight_btn.addActionListener(lambda e: self._highlight_results())
        
        goto_btn = JButton("Go to Address")
        goto_btn.addActionListener(lambda e: self._goto_selected())
        
        bottom_panel.add(self.status_label)
        bottom_panel.add(Box.createHorizontalStrut(20))
        bottom_panel.add(goto_btn)
        bottom_panel.add(highlight_btn)
        
        # Add components to main panel
        self.panel.add(query_wrapper, BorderLayout.NORTH)
        self.panel.add(scroll_pane, BorderLayout.CENTER)
        self.panel.add(bottom_panel, BorderLayout.SOUTH)
        
        # Enable Enter key for search
        self.query_field.addActionListener(lambda e: self._run_query())
    
    def getPanel(self):
        return self.panel
    
    def _run_query(self):
        """Execute the query"""
        query = self.query_field.getText().strip()
        if not query:
            return
        
        self.status_label.setText("Searching...")
        self.table_model.setRowCount(0)
        
        try:
            parser = QueryParser()
            parsed_query = parser.parse(query)
            
            # Debug parsed query
            print("\n=== Query Debug ===")
            print("Raw query: {}".format(query))
            print("Parsed type: {}".format(parsed_query.type))
            print("Constraints: {}".format(parsed_query.constraints))
            
            self.results = self.engine.find_pattern(parsed_query.type, **parsed_query.constraints)
            # Populate table
            for i, result in enumerate(self.results):
                row_data = [
                    i + 1,
                    result['type'],
                    self._format_result(result),
                    str(result['address']) if result['address'] else "N/A"
                ]
                self.table_model.addRow(row_data)
            
            self.status_label.setText("Found {} matches".format(len(self.results)))
            
        except Exception as e:
            self.status_label.setText("Error: {}".format(str(e)))
            print("Query error: {}".format(e))
            import traceback
            traceback.print_exc()
    
    def _format_result(self, result):
        """Format result for display"""
        if result['type'] == 'assignment':
            return "[{}] {} {} {}".format(result.get('function', ''), result['variable'], result['operator'], result['value'])
        elif result['type'] == 'function_call':
            args_str = ', '.join(result['arguments'])
            return "[{}] {}({})".format(result.get('containing_function', ''), result['function'], args_str)
        elif result['type'] == 'variable':
            return "[{}] {} (context: {})".format(result.get('function', ''), result['name'], result['context'])
        elif result['type'] == 'operator':
            operands_str = " {} ".format(result['operator']).join(result['operands'])
            return "[{}] {}".format(result.get('function', ''), operands_str)
        elif result['type'] == 'control_flow':
            return "[{}] {}: {}".format(result.get('function', ''), result['keyword'], result['condition'])
        return "Unknown"
    
    def _clear_results(self):
        """Clear all results"""
        self.table_model.setRowCount(0)
        self.results = []
        self.status_label.setText("Cleared")
        self.query_field.setText("")
    
    def _on_row_selected(self, event):
        """Handle row selection"""
        row = self.results_table.getSelectedRow()
        if row >= 0 and row < len(self.results):
            result = self.results[row]
            if result['address']:
                # Navigate to address in listing
                goTo(result['address'])
    
    def _goto_selected(self):
        """Go to selected result address"""
        row = self.results_table.getSelectedRow()
        if row >= 0 and row < len(self.results):
            result = self.results[row]
            if result['address']:
                goTo(result['address'])
    
    def _highlight_results(self):
        """Highlight all results"""
        if self.results:
            highlight_results(self.results)
            self.status_label.setText(f"Highlighted {len(self.results)} results")

def show_query_window():
    """Show the query window as a simple dialog"""
    # For PyGhidra, let's create a simple JFrame window instead
    frame = JFrame("AST Pattern Query")
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    
    engine = ASTPatternEngine()
    query_panel = ASTQueryPanel(engine)
    
    frame.add(query_panel.getPanel())
    frame.setSize(800, 600)
    frame.setLocationRelativeTo(None)
    frame.setVisible(True)

# Run the GUI
show_query_window()