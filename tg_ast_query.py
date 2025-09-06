# AST Pattern Query Engine for Ghidra Decompiler
#@author Tomer Goldschmidt
#@category _NEW_
#@keybinding ctrl shift Q
#@menupath Tools.Analysis.AST Pattern Query
#@toolbar 
#@runtime PyGhidra

from ghidra.app.decompiler import *
from ghidra.program.model.listing import Function
from java.awt import Color
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
        
        # Assignment: var = expr;
        if query.endswith(';') and '=' in query:
            self.type = 'assignment'
            var, expr = query[:-1].split('=', 1)
            var = var.strip()
            expr = expr.strip()
            self.constraints['var_pattern'] = self._convert_to_regex(var)
            self.constraints['value_pattern'] = self._convert_to_regex(expr) if expr != '_' else None
            return self
        
        # Function call: func(args);
        elif query.endswith(');') and '(' in query:
            self.type = 'function_call'
            func_part, args_part = query[:-1].split('(', 1)
            func_name = func_part.strip()
            args = [arg.strip() for arg in args_part.split(',')] if args_part else []
            self.constraints['func_pattern'] = self._convert_to_regex(func_name)
            if args != ['_']:  # Ignore wildcard args
                self.constraints['arg_count'] = len(args)
            return self
        
        # Control flow: if(expr), while(expr), etc.
        elif any(query.startswith(kw) for kw in ['if(', 'while(', 'for(', 'switch(']):
            self.type = 'control_flow'
            kw_end = query.find('(')
            self.constraints['flow_type'] = query[:kw_end]
            condition = query[kw_end+1:-1].strip()
            self.constraints['condition_pattern'] = self._convert_to_regex(condition) if condition != '_' else None
            return self
        
        # Operator: expr1 op expr2
        elif any(op in query for op in ['+', '-', '*', '/', '%', '&', '|', '^', '~', '<<', '>>', '==', '!=', '<', '>', '<=', '>=', '&&', '||', '!']):
            self.type = 'operator'
            for op in ['&&', '||', '<<', '>>', '<=', '>=', '==', '!=', '+', '-', '*', '/', '%', '&', '|', '^', '~', '<', '>']:
                if op in query:
                    self.constraints['op_type'] = self._map_operator_to_category(op)
                    operands = query.split(op, 1)
                    self.constraints['operand_pattern'] = self._convert_to_regex(operands[0].strip()) if operands[0].strip() != '_' else None
                    break
            return self
        
        # Variable usage: var
        else:
            self.type = 'variable'
            self.constraints['var_pattern'] = self._convert_to_regex(query)
            return self
    
    def _convert_to_regex(self, pattern):
        """Convert weggli-like pattern to regex"""
        if pattern == '_':
            return None
        pattern = re.escape(pattern)
        pattern = pattern.replace(r'\*', '.*').replace(r'\?', '.')
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
        
    def __del__(self):
        if hasattr(self, 'decompiler'):
            self.decompiler.dispose()
    
    def get_ast(self, function):
        """Get or cache the AST for a function"""
        func_addr = function.getEntryPoint()
        
        if func_addr not in self.ast_cache:
            results = self.decompiler.decompileFunction(function, 30, monitor)
            if results.decompileCompleted():
                self.ast_cache[func_addr] = results.getCCodeMarkup()
            else:
                return None
                
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
        Find patterns in the AST based on parsed query
        """
        self.results = []
        
        if pattern_type == 'assignment':
            self._find_assignments(**kwargs)
        elif pattern_type == 'function_call':
            self._find_function_calls(**kwargs)
        elif pattern_type == 'variable':
            self._find_variables(**kwargs)
        elif pattern_type == 'operator':
            self._find_operators(**kwargs)
        elif pattern_type == 'control_flow':
            self._find_control_flow(**kwargs)
        
        return self.results
    
    def _find_assignments(self, var_pattern=None, value_pattern=None, operator=None):
        """Find assignment operations"""
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
                            
                            if value_pattern and value_text and not re.search(value_pattern, value_text):
                                return True
                            
                            self.results.append({
                                'type': 'assignment',
                                'variable': var_name,
                                'operator': op_text,
                                'value': value_text,
                                'node': node,
                                'parent': parent,
                                'address': node.getMinAddress()
                            })
            
            return True
        
        func = getFunctionContaining(currentAddress)
        if func:
            ast = self.get_ast(func)
            if ast:
                self.traverse_ast(ast, check_assignment)
    
    def _find_function_calls(self, func_pattern=None, arg_count=None, in_condition=False):
        """Find function calls"""
        def check_function_call(node, depth, parent):
            if isinstance(node, ClangFuncNameToken):
                func_name = node.getText()
                
                if func_pattern and not re.match(func_pattern, func_name):
                    return True
                
                args = []
                if parent and arg_count is not None:
                    args = self._count_function_args(parent)
                    if len(args) != arg_count:
                        return True
                
                if in_condition and not self._is_in_condition(node, parent):
                    return True
                
                self.results.append({
                    'type': 'function_call',
                    'function': func_name,
                    'arguments': args,
                    'node': node,
                    'parent': parent,
                    'address': node.getMinAddress()
                })
            
            return True
        
        func = getFunctionContaining(currentAddress)
        if func:
            ast = self.get_ast(func)
            if ast:
                self.traverse_ast(ast, check_function_call)
    
    def _find_variables(self, var_pattern=None, context=None):
        """Find variable usage"""
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
                    'address': node.getMinAddress()
                })
            
            return True
        
        func = getFunctionContaining(currentAddress)
        if func:
            ast = self.get_ast(func)
            if ast:
                self.traverse_ast(ast, check_variable)
    
    def _find_operators(self, op_type=None, operand_pattern=None):
        """Find operators"""
        def check_operator(node, depth, parent):
            if isinstance(node, ClangOpToken):
                op_text = node.getText()
                
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
                
                if operand_pattern:
                    match_found = False
                    for operand in operands:
                        if re.search(operand_pattern, operand):
                            match_found = True
                            break
                    if not match_found:
                        return True
                
                self.results.append({
                    'type': 'operator',
                    'operator': op_text,
                    'operands': operands,
                    'node': node,
                    'parent': parent,
                    'address': node.getMinAddress()
                })
            
            return True
        
        func = getFunctionContaining(currentAddress)
        if func:
            ast = self.get_ast(func)
            if ast:
                self.traverse_ast(ast, check_operator)
    
    def _find_control_flow(self, flow_type=None, condition_pattern=None):
        """Find control flow structures"""
        def check_control_flow(node, depth, parent):
            if isinstance(node, ClangSyntaxToken):
                syntax = node.getText()
                
                control_keywords = ['if', 'else', 'while', 'for', 'do', 'switch', 'case', 'return', 'break', 'continue', 'goto']
                
                if syntax in control_keywords:
                    if flow_type and syntax != flow_type:
                        return True
                    
                    condition = self._get_control_condition(node, parent)
                    
                    if condition_pattern and condition and not re.search(condition_pattern, condition):
                        return True
                    
                    self.results.append({
                        'type': 'control_flow',
                        'keyword': syntax,
                        'condition': condition,
                        'node': node,
                        'parent': parent,
                        'address': node.getMinAddress()
                    })
            
            return True
        
        func = getFunctionContaining(currentAddress)
        if func:
            ast = self.get_ast(func)
            if ast:
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
    from jpype import JImplements, JOverride
    
    @JImplements(CTokenHighlightMatcher)
    class QueryHighlighter:
        def __init__(self, results):
            self.nodes_to_highlight = set()
            for r in results:
                if 'node' in r:
                    self.nodes_to_highlight.add(r['node'])
        
        @JOverride
        def start(self, root):
            pass
        
        @JOverride
        def getTokenHighlight(self, token):
            if token in self.nodes_to_highlight:
                return Color.CYAN
            return None
        
        @JOverride
        def end(self):
            pass
    
    tool = state.getTool()
    service = tool.getService(DecompilerHighlightService)
    
    if service:
        matcher = QueryHighlighter(results)
        service.createHighlighter("AST_Query_Results", matcher)
        print("Results highlighted in cyan in the decompiler")

def run_query():
    """Interactive query interface"""
    print("=" * 60)
    print("AST Pattern Query Engine")
    print("=" * 60)
    
    engine = ASTPatternEngine()
    
    print("\nEnter a query (weggli-like syntax):")
    print("Examples:")
    print("- TG_* = _; (assignments to variables starting with TG_)")
    print("- strcmp(_,_); (strcmp or strncmp calls)")
    print("- if(_) (if statements)")
    print("- _ & _ (bitwise AND operations)")
    print("Enter 'exit' to quit")
    
    while True:
        query = askString("Query", "Enter query (or 'exit' to quit):")
        if query.lower() == 'exit':
            break
            
        parser = QueryParser()
        parsed_query = parser.parse(query)
        
        results = engine.find_pattern(parsed_query.type, **parsed_query.constraints)
        
        if results:
            print(f"\nFound {len(results)} matches:")
            print("-" * 60)
            
            for i, result in enumerate(results[:20]):
                if result['type'] == 'assignment':
                    print(f"{i+1}. {result['variable']} {result['operator']} {result['value']}")
                    print(f"   Address: {result['address']}")
                
                elif result['type'] == 'function_call':
                    args_str = ', '.join(result['arguments'])
                    print(f"{i+1}. {result['function']}({args_str})")
                    print(f"   Address: {result['address']}")
                
                elif result['type'] == 'variable':
                    print(f"{i+1}. Variable: {result['name']} (context: {result['context']})")
                    print(f"   Address: {result['address']}")
                
                elif result['type'] == 'operator':
                    operands_str = f" {result['operator']} ".join(result['operands'])
                    print(f"{i+1}. Operation: {operands_str}")
                    print(f"   Address: {result['address']}")
                
                elif result['type'] == 'control_flow':
                    print(f"{i+1}. {result['keyword']}: {result['condition']}")
                    print(f"   Address: {result['address']}")
            
            if len(results) > 20:
                print(f"\n... and {len(results) - 20} more results")
            
            if askYesNo("Highlight Results", "Would you like to highlight these in the decompiler?"):
                highlight_results(results)
        else:
            print("\nNo matches found")

# Run the query interface
run_query()