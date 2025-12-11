# AST Pattern Query Engine for Ghidra Decompiler - Tree-sitter Style
#@author Tomer Goldschmidt
#@category _NEW_
#@keybinding ctrl shift Q
#@menupath Tools.Analysis.AST Pattern Query
#@toolbar 
#@runtime PyGhidra

from ghidra.app.decompiler import *
from ghidra.program.model.listing import Function
from java.awt import Color, BorderLayout, FlowLayout, Dimension, Font
from javax.swing import *
from javax.swing.table import DefaultTableModel
from javax.swing.text import DefaultHighlighter
import re
import json
from collections import defaultdict

class TokenWrapper:
    """Lightweight wrapper for Ghidra tokens to provide uniform interface"""
    def __init__(self, token):
        self.token = token
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
            op_text = self.token.getText()
            if op_text == '=':
                return 'assignment'
            elif op_text in ['==', '!=', '<', '>', '<=', '>=']:
                return 'comparison'
            elif op_text in ['+', '-', '*', '/', '%']:
                return 'arithmetic'
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
    
    def get_children(self):
        """Get child tokens using Ghidra's iterator"""
        children = []
        if hasattr(self.token, 'tokenIterator'):
            for child_token in self.token.tokenIterator(False):
                if child_token != self.token:  # Skip self
                    children.append(TokenWrapper(child_token))
        return children

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
        self.next_sibling = None  # For sequential patterns
        self.alternatives = []  # For OR patterns
        self.strict = False  # Strict matching mode
        self.not_pattern = None  # For NOT: patterns
        
    def matches(self, token_wrapper, captures=None):
        """Check if this pattern matches the given token"""
        if captures is None:
            captures = {}
        
        # Handle NOT patterns first
        if self.not_pattern:
            not_captures = dict(captures)
            if self.not_pattern.matches(token_wrapper, not_captures):
                return False  # If NOT pattern matches, this pattern fails
            
        # Handle wildcards
        if self.wildcard:
            return True
            
        # Handle negation
        if self.negated:
            return not self._match_impl(token_wrapper, captures)
            
        # Handle alternatives (OR)
        if self.alternatives:
            for alt_pattern in self.alternatives:
                alt_captures = dict(captures)
                if alt_pattern.matches(token_wrapper, alt_captures):
                    captures.update(alt_captures)
                    return True
            return False
            
        return self._match_impl(token_wrapper, captures)
    
    def _match_impl(self, token_wrapper, captures):
        """Implementation of pattern matching"""
        # Type matching
        if self.type and token_wrapper.type != self.type:
            return False
            
        # Text matching
        if 'text' in self.constraints:
            pattern_text = self.constraints['text']
            if pattern_text.startswith('$'):
                # Variable capture
                cap_name = pattern_text[1:]
                if cap_name in captures:
                    if captures[cap_name] != token_wrapper.text:
                        return False
                else:
                    captures[cap_name] = token_wrapper.text
            elif pattern_text == '_':
                # Wildcard - matches anything
                return True
            elif pattern_text.startswith('_(') and pattern_text.endswith(')'):
                # Subexpression wildcard _(..)
                inner_pattern = pattern_text[2:-1]
                return self._match_subexpression(token_wrapper, inner_pattern, captures)
            else:
                # Literal or regex match
                if not self._matches_text(pattern_text, token_wrapper.text):
                    return False
        
        # Match children if specified
        if self.children:
            children = token_wrapper.get_children()
            if not self._match_children(children, captures):
                return False
                
        return True
    
    def _match_subexpression(self, token_wrapper, pattern, captures):
        """Match subexpression patterns like _(test) """
        # This would match any expression containing the pattern
        # For now, simple text search within the expression
        if hasattr(token_wrapper.token, 'toString'):
            expr_text = token_wrapper.token.toString()
            return pattern in expr_text
        return False
    
    def _matches_text(self, pattern, text):
        """Check if text matches pattern (supports wildcards and regex)"""
        if pattern == text:
            return True
        
        # Regex pattern (enclosed in /)
        if pattern.startswith('/') and pattern.endswith('/'):
            regex = pattern[1:-1]
            try:
                return bool(re.match(regex, text))
            except:
                return False
        
        # Convert wildcards to regex
        if '*' in pattern or '?' in pattern or '..' in pattern:
            regex = pattern.replace('*', r'[a-zA-Z0-9_]*')
            regex = regex.replace('?', r'[a-zA-Z0-9_]')
            regex = regex.replace('..', r'.*')
            regex = '^' + regex + '$'
            return bool(re.match(regex, text))
            
        return False
    
    def _match_attribute(self, token_wrapper, attr_name, expected_value):
        """Match custom attributes"""
        # Example: match token properties
        if attr_name == "address" and token_wrapper.address:
            return str(token_wrapper.address) == expected_value
        return False
    
    def _match_children(self, children, captures):
        """Match child patterns against token's children"""
        # This would need more sophisticated matching for sequences, alternatives, etc.
        # For now, simple ordered matching
        if len(self.children) > len(children):
            return False
            
        for pattern_child, child in zip(self.children, children):
            if not pattern_child.matches(child, captures):
                return False
                
        return True

class QueryCompiler:
    """Compiles C-like query strings into Pattern objects"""
    
    def __init__(self):
        self.tokens = []
        self.pos = 0
        self.strict_mode = False
        
    def compile(self, query_str):
        """Compile a C-like query string into a Pattern tree"""
        print("Compiling C-like query: '{}'".format(query_str))
        
        # Check for special directives
        if query_str.strip().startswith('strict:'):
            self.strict_mode = True
            query_str = query_str.replace('strict:', '').strip()
            print("Strict mode enabled")
        
        # Handle NOT: patterns
        if 'NOT:' in query_str or 'not:' in query_str:
            return self._parse_not_pattern(query_str)
        
        self.tokens = self._tokenize_c_like(query_str)
        print("Tokens: {}".format(self.tokens))
        self.pos = 0
        pattern = self._parse_c_expression()
        
        if pattern:
            print("Compiled pattern type: {}, constraints: {}".format(pattern.type, pattern.constraints))
        return pattern
    
    def _parse_not_pattern(self, query_str):
        """Parse patterns with NOT: clauses"""
        # Split by NOT: or not:
        import re
        parts = re.split(r'(?i)\s*not:\s*', query_str)
        
        if len(parts) == 1:
            # No NOT clause, parse normally
            return self.compile(parts[0])
        
        # Create main pattern from first part
        main_pattern = self.compile(parts[0].strip()) if parts[0].strip() else None
        
        # Create NOT patterns from remaining parts
        for not_part in parts[1:]:
            if not_part.strip():
                not_pattern = self.compile(not_part.strip())
                if main_pattern:
                    main_pattern.not_pattern = not_pattern
                else:
                    # If no main pattern, create a wildcard with NOT
                    main_pattern = Pattern('_')
                    main_pattern.wildcard = True
                    main_pattern.not_pattern = not_pattern
                break  # For now, handle only one NOT clause
        
        return main_pattern
    
    def _tokenize_c_like(self, query_str):
        """Enhanced tokenizer for C-like syntax"""
        tokens = []
        current = ""
        in_string = False
        in_char = False
        
        i = 0
        while i < len(query_str):
            char = query_str[i]
            
            # Handle string literals
            if char == '"' and not in_char:
                if in_string:
                    current += char
                    tokens.append(current)
                    current = ""
                    in_string = False
                else:
                    if current:
                        tokens.append(current)
                        current = ""
                    current += char
                    in_string = True
            elif in_string:
                current += char
            # Handle char literals
            elif char == "'" and not in_string:
                if in_char:
                    current += char
                    tokens.append(current)
                    current = ""
                    in_char = False
                else:
                    if current:
                        tokens.append(current)
                        current = ""
                    current += char
                    in_char = True
            elif in_char:
                current += char
            # Handle multi-character operators
            elif i + 1 < len(query_str) and query_str[i:i+2] in ['==', '!=', '<=', '>=', '->', '&&', '||', '++', '--', '<<', '>>', '+=', '-=', '*=', '/=']:
                if current:
                    tokens.append(current)
                    current = ""
                tokens.append(query_str[i:i+2])
                i += 1  # Skip next char
            # Handle single character tokens
            elif char in '(){}[];,=<>!&|+-*/%^~.':
                if current:
                    tokens.append(current)
                    current = ""
                tokens.append(char)
            # Handle whitespace
            elif char in ' \t\n\r':
                if current:
                    tokens.append(current)
                    current = ""
            else:
                current += char
            
            i += 1
        
        if current:
            tokens.append(current)
            
        return tokens
    
    def _parse_c_expression(self):
        """Parse C-like expressions"""
        return self._parse_assignment()
    
    def _parse_assignment(self):
        """Parse assignment expressions"""
        left = self._parse_logical_or()
        
        if self.pos < len(self.tokens) and self.tokens[self.pos] in ['=', '+=', '-=', '*=', '/=']:
            op = self.tokens[self.pos]
            self.pos += 1
            right = self._parse_assignment()
            
            pattern = Pattern('{} {} {}'.format(left.raw if left else '', op, right.raw if right else ''))
            pattern.type = 'assignment' if op == '=' else 'compound_assignment'
            pattern.children = [left, right] if left and right else []
            return pattern
        
        return left
    
    def _parse_logical_or(self):
        """Parse logical OR expressions"""
        left = self._parse_logical_and()
        
        while self.pos < len(self.tokens) and self.tokens[self.pos] == '||':
            self.pos += 1
            right = self._parse_logical_and()
            
            if not left.alternatives:
                left.alternatives = []
            left.alternatives.append(right)
        
        return left
    
    def _parse_logical_and(self):
        """Parse logical AND expressions"""
        left = self._parse_equality()
        
        while self.pos < len(self.tokens) and self.tokens[self.pos] == '&&':
            self.pos += 1
            right = self._parse_equality()
            
            and_pattern = Pattern('AND')
            and_pattern.type = 'and'
            and_pattern.children = [left, right]
            left = and_pattern
        
        return left
    
    def _parse_equality(self):
        """Parse equality expressions"""
        left = self._parse_relational()
        
        if self.pos < len(self.tokens) and self.tokens[self.pos] in ['==', '!=']:
            op = self.tokens[self.pos]
            self.pos += 1
            right = self._parse_relational()
            
            pattern = Pattern('{} {} {}'.format(left.raw if left else '', op, right.raw if right else ''))
            pattern.type = 'comparison'
            pattern.constraints['operator'] = op
            pattern.children = [left, right] if left and right else []
            return pattern
        
        return left
    
    def _parse_relational(self):
        """Parse relational expressions"""
        return self._parse_additive()
    
    def _parse_additive(self):
        """Parse additive expressions"""
        return self._parse_multiplicative()
    
    def _parse_multiplicative(self):
        """Parse multiplicative expressions"""
        return self._parse_unary()
    
    def _parse_unary(self):
        """Parse unary expressions"""
        if self.pos < len(self.tokens) and self.tokens[self.pos] in ['!', '~', '-', '+', '*', '&']:
            op = self.tokens[self.pos]
            self.pos += 1
            operand = self._parse_postfix()
            
            if op == '!':
                # Negation
                if operand:
                    operand.negated = True
                return operand
            else:
                pattern = Pattern(op + (operand.raw if operand else ''))
                pattern.type = 'unary'
                pattern.constraints['operator'] = op
                if operand:
                    pattern.children = [operand]
                return pattern
        
        return self._parse_postfix()
    
    def _parse_postfix(self):
        """Parse postfix expressions"""
        left = self._parse_primary()
        
        while self.pos < len(self.tokens):
            if self.tokens[self.pos] == '(':
                # Function call
                return self._parse_function_call_from_primary(left)
            elif self.tokens[self.pos] == '[':
                # Array access
                self.pos += 1
                index = self._parse_c_expression()
                if self.pos < len(self.tokens) and self.tokens[self.pos] == ']':
                    self.pos += 1
                
                pattern = Pattern('{}[{}]'.format(left.raw if left else '', index.raw if index else ''))
                pattern.type = 'array_access'
                pattern.children = [left, index] if left and index else []
                left = pattern
            elif self.tokens[self.pos] in ['->', '.']:
                # Member access
                op = self.tokens[self.pos]
                self.pos += 1
                if self.pos < len(self.tokens):
                    member = self._parse_primary()
                    pattern = Pattern('{}{}{}'.format(left.raw if left else '', op, member.raw if member else ''))
                    pattern.type = 'member_access'
                    pattern.children = [left, member] if left and member else []
                    left = pattern
                else:
                    break
            else:
                break
        
        return left
    
    def _parse_primary(self):
        """Parse primary expressions"""
        if self.pos >= len(self.tokens):
            return None
        
        token = self.tokens[self.pos]
        
        # Handle parentheses
        if token == '(':
            self.pos += 1
            expr = self._parse_c_expression()
            if self.pos < len(self.tokens) and self.tokens[self.pos] == ')':
                self.pos += 1
            return expr
        
        # Handle braces for compound statements
        if token == '{':
            return self._parse_compound_statement()
        
        # Handle wildcards
        if token == '_':
            self.pos += 1
            pattern = Pattern('_')
            pattern.wildcard = True
            return pattern
        
        # Handle subexpression wildcards
        if token.startswith('_(') and token.endswith(')'):
            self.pos += 1
            pattern = Pattern(token)
            pattern.wildcard = True
            pattern.constraints['text'] = token
            return pattern
        
        # Handle variables
        if token.startswith('$'):
            self.pos += 1
            pattern = Pattern(token)
            pattern.constraints['text'] = token
            return pattern
        
        # Handle function calls (lookahead)
        if self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1] == '(':
            return self._parse_function_call()
        
        # Handle literals and identifiers
        self.pos += 1
        pattern = Pattern(token)
        
        # Determine pattern type based on token
        if token.isdigit() or (token.startswith('0x') and len(token) > 2):
            pattern.type = 'constant'
        elif token.startswith('"') and token.endswith('"'):
            pattern.type = 'string_literal'
        elif token.startswith("'") and token.endswith("'"):
            pattern.type = 'char_literal'
        elif token in ['if', 'while', 'for', 'switch', 'do', 'return', 'break', 'continue']:
            pattern.type = 'control_flow'
        elif token in ['int', 'char', 'void', 'float', 'double', 'short', 'long', 'unsigned', 'signed']:
            pattern.type = 'type'
        else:
            # Default to identifier/variable
            pattern.type = None  # Let token wrapper determine
        
        pattern.constraints['text'] = token
        return pattern
    
    def _parse_compound_statement(self):
        """Parse compound statements { ... }"""
        if self.pos >= len(self.tokens) or self.tokens[self.pos] != '{':
            return None
        
        self.pos += 1  # Skip '{'
        statements = []
        
        while self.pos < len(self.tokens) and self.tokens[self.pos] != '}':
            stmt = self._parse_c_expression()
            if stmt:
                statements.append(stmt)
            
            # Skip semicolons
            if self.pos < len(self.tokens) and self.tokens[self.pos] == ';':
                self.pos += 1
        
        if self.pos < len(self.tokens) and self.tokens[self.pos] == '}':
            self.pos += 1  # Skip '}'
        
        pattern = Pattern('{ ... }')
        pattern.type = 'compound'
        pattern.children = statements
        return pattern
    
    def _parse_function_call(self):
        """Parse function call patterns"""
        func_name = self.tokens[self.pos]
        self.pos += 1  # Skip function name
        
        if self.pos >= len(self.tokens) or self.tokens[self.pos] != '(':
            # Not a function call, backtrack
            self.pos -= 1
            return self._parse_primary()
        
        return self._parse_function_call_from_name(func_name)
    
    def _parse_function_call_from_primary(self, func_pattern):
        """Parse function call from existing primary expression"""
        if not func_pattern:
            return None
        
        func_name = func_pattern.raw
        return self._parse_function_call_from_name(func_name)
    
    def _parse_function_call_from_name(self, func_name):
        """Parse function call given the function name"""
        self.pos += 1  # Skip '('
        
        pattern = Pattern('{}(...)'.format(func_name))
        pattern.type = 'function_name'  # Match against function name tokens
        pattern.constraints['text'] = func_name
        
        # Parse arguments
        args = []
        while self.pos < len(self.tokens) and self.tokens[self.pos] != ')':
            if self.tokens[self.pos] == ',':
                self.pos += 1
                continue
            
            arg_pattern = self._parse_c_expression()
            if arg_pattern:
                args.append(arg_pattern)
        
        pattern.constraints['arguments'] = args
        pattern.children = args
        
        if self.pos < len(self.tokens) and self.tokens[self.pos] == ')':
            self.pos += 1
        
        return pattern

class ASTQueryEngine:
    """Main query engine using Tree-sitter-like approach"""
    
    def __init__(self):
        self.debug = True  # Enable debugging by default
        self.highlight_color = Color.YELLOW
        self.current_highlights = []  # Store highlighted tokens
        print("ASTQueryEngine initialized")
        
    def query(self, pattern_str, func=None):
        """Execute a query against the AST"""
        print("\n=== Starting query ===")
        print("Pattern: '{}'".format(pattern_str))
        
        # Clear previous highlights
        self._clear_highlights()
        
        # Compile the pattern
        compiler = QueryCompiler()
        pattern = compiler.compile(pattern_str)
        
        if not pattern:
            print("Failed to compile pattern")
            return [], {}
        
        # Get the current location's decompilation
        try:
            func = currentLocation.decompile.function
            if not func:
                print("No function found in decompilation data")
                return [], {}
                
            print("Searching in function: {}".format(func.getName()))
            
            # Get the C code markup (this is Ghidra's AST)
            markup = currentLocation.decompile.cCodeMarkup
            if not markup:
                print("Failed to get code markup")
                return [], {}
                
            print("Got markup, class: {}".format(markup.__class__.__name__))
            
            # Search the AST
            results = []
            captures = {}
            self._search_tokens(markup, pattern, results, captures, func.getName(), 0)
            
            # Highlight matches
            for result in results:
                self._highlight_match(result)
            
            print("Search complete. Found {} results".format(len(results)))
            return results, captures
            
        except Exception as e:
            print("Error in query: {}".format(e))
            import traceback
            traceback.print_exc()
            return [], {}
    
    def _search_tokens(self, token, pattern, results, captures, func_name, depth=0):
        """Recursively search tokens for pattern matches"""
        indent = "  " * depth
        
        # Handle AND patterns
        if hasattr(pattern, 'type') and pattern.type == 'and':
            # Both children must match
            temp_results = []
            for child_pattern in pattern.children:
                child_results = []
                child_captures = dict(captures)
                self._search_tokens(token, child_pattern, child_results, child_captures, func_name, depth)
                temp_results.append((child_results, child_captures))
            
            # If all children matched, add to results
            if all(r for r, _ in temp_results):
                for r, c in temp_results:
                    results.extend(r)
                    captures.update(c)
            return
        
        # Wrap the token
        wrapped = TokenWrapper(token)
        
        if self.debug and depth < 3:  # Limit debug output depth
            print("{}Token: type='{}', text='{}', class='{}'".format(
                indent, wrapped.type, wrapped.text[:20] if wrapped.text else "", 
                token.__class__.__name__))
        
        # Try to match at this token
        local_captures = dict(captures)
        
        if pattern.matches(wrapped, local_captures):
            print("{}MATCH FOUND! type='{}', text='{}'".format(
                indent, wrapped.type, wrapped.text))
            
            # Get context information
            context = self._get_match_context(token)
            
            # Found a match
            result = {
                'token': token,
                'type': wrapped.type,
                'text': wrapped.text,
                'address': wrapped.address,
                'function': func_name,
                'captures': dict(local_captures),
                'line_number': self._get_line_number(token),
                'context': context,
                'parent_type': self._get_parent_type(token),
                'siblings': self._get_siblings_info(token)
            }
            results.append(result)
            
            # Update global captures
            captures.update(local_captures)
        
        # Recursively search children using Ghidra's iterator
        if hasattr(token, 'tokenIterator'):
            try:
                # Use tokenIterator to get all child tokens
                child_count = 0
                for child_token in token.tokenIterator(False):  # False = don't include self
                    if child_token != token:  # Extra safety check
                        child_count += 1
                        self._search_tokens(child_token, pattern, results, captures, func_name, depth + 1)
                
                if self.debug and child_count > 0 and depth < 2:
                    print("{}Processed {} children".format(indent, child_count))
                    
            except Exception as e:
                print("{}Error iterating children: {}".format(indent, e))
    
    def _get_match_context(self, token):
        """Get surrounding code context for a match"""
        try:
            # Get the line containing this token
            if hasattr(token, 'getLineParent'):
                line_parent = token.getLineParent()
                if line_parent:
                    return line_parent.toString()
        except:
            pass
        return ""
    
    def _get_line_number(self, token):
        """Get line number for token"""
        try:
            if hasattr(token, 'getLineParent'):
                line_parent = token.getLineParent()
                # This is approximate - Ghidra doesn't directly provide line numbers
                return "~"  # Placeholder
        except:
            pass
        return "?"
    
    def _get_parent_type(self, token):
        """Get the type of the parent token"""
        try:
            if hasattr(token, 'Parent'):
                parent = token.Parent()
                if parent:
                    return TokenWrapper(parent).type
        except:
            pass
        return "unknown"
    
    def _get_siblings_info(self, token):
        """Get information about sibling tokens"""
        siblings = []
        try:
            if hasattr(token, 'Parent'):
                parent = token.Parent()
                if parent and hasattr(parent, 'tokenIterator'):
                    for sibling in parent.tokenIterator(False):
                        if sibling != token:
                            wrapped = TokenWrapper(sibling)
                            siblings.append({'type': wrapped.type, 'text': wrapped.text[:20]})
                            if len(siblings) >= 3:  # Limit to 3 siblings
                                break
        except:
            pass
        return siblings
    
    def _highlight_match(self, result):
        """Highlight a matched token in the decompiler window"""
        token = result['token']
        if hasattr(token, 'setHighlight'):
            try:
                token.setHighlight(self.highlight_color)
                self.current_highlights.append(token)
            except:
                pass
    
    def _clear_highlights(self):
        """Clear all highlights"""
        for token in self.current_highlights:
            if hasattr(token, 'setHighlight'):
                try:
                    token.setHighlight(None)
                except:
                    pass
        self.current_highlights = []
    
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
        
        # Debug toggle
        self.debug_checkbox = JCheckBox("Debug", True)
        self.debug_checkbox.addActionListener(lambda e: self._toggle_debug())
        
        # Clear button
        clear_btn = JButton("Clear")
        clear_btn.addActionListener(lambda e: self._clear_results())
        
        # Highlight color button
        highlight_btn = JButton("Highlight Color")
        highlight_btn.addActionListener(lambda e: self._choose_highlight_color())
        
        top_panel.add(JLabel("Query:"))
        top_panel.add(self.query_field)
        top_panel.add(search_btn)
        top_panel.add(self.debug_checkbox)
        top_panel.add(highlight_btn)
        top_panel.add(clear_btn)
        
        # Help text with C-like examples
        help_text = JTextArea(10, 60)
        help_text.setText(
            "C-like Query Syntax Examples:\n" +
            "  malloc($size)           - Find malloc calls, capture size argument\n" +
            "  { _ $buf[_]; memcpy($buf,_,_); }  - Stack buffer with memcpy\n" +
            "  $x = $y                 - Find all assignments\n" +
            "  if ($cond) { $body }    - Find if statements\n" +
            "  strict: func();         - Exact function call matching only\n" +
            "  NOT: $ptr == NULL       - Find code without NULL checks\n" +
            "  $func(_); NOT: if(_)    - Function calls not in if statements\n" +
            "  $ret = snprintf($buf,_,_); $buf[$ret] = _;  - Potential buffer issues\n" +
            "  _($test)                - Any expression involving 'test'\n" +
            "  { _* $p; NOT: $p = _; $func(&$p); }  - Uninitialized pointers"
        )
        help_text.setEditable(False)
        help_text.setBackground(self.panel.getBackground())
        
        # Query panel wrapper
        query_wrapper = JPanel(BorderLayout())
        query_wrapper.add(top_panel, BorderLayout.NORTH)
        query_wrapper.add(help_text, BorderLayout.SOUTH)
        
        # Results table with more columns
        self.table_model = DefaultTableModel()
        self.table_model.addColumn("#")
        self.table_model.addColumn("Function")
        self.table_model.addColumn("Type")
        self.table_model.addColumn("Match")
        self.table_model.addColumn("Context")
        self.table_model.addColumn("Address")
        self.table_model.addColumn("Parent")
        
        self.results_table = JTable(self.table_model)
        self.results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.results_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_row_selected(e) if not e.getValueIsAdjusting() else None
        )
        
        # Set column widths
        self.results_table.getColumnModel().getColumn(0).setPreferredWidth(30)
        self.results_table.getColumnModel().getColumn(1).setPreferredWidth(100)
        self.results_table.getColumnModel().getColumn(2).setPreferredWidth(80)
        self.results_table.getColumnModel().getColumn(3).setPreferredWidth(200)
        self.results_table.getColumnModel().getColumn(4).setPreferredWidth(300)
        self.results_table.getColumnModel().getColumn(5).setPreferredWidth(80)
        self.results_table.getColumnModel().getColumn(6).setPreferredWidth(80)
        
        scroll_pane = JScrollPane(self.results_table)
        scroll_pane.setPreferredSize(Dimension(900, 400))
        
        # Details panel
        self.details_area = JTextArea(5, 80)
        self.details_area.setEditable(False)
        self.details_area.setFont(Font(Font.MONOSPACED, Font.PLAIN, 12))
        details_scroll = JScrollPane(self.details_area)
        details_scroll.setPreferredSize(Dimension(900, 100))
        
        # Results wrapper with split pane
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll_pane, details_scroll)
        split_pane.setDividerLocation(400)
        
        # Bottom panel
        bottom_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        
        self.status_label = JLabel("Ready")
        self.captures_label = JLabel("")
        
        goto_btn = JButton("Go to Address")
        goto_btn.addActionListener(lambda e: self._goto_selected())
        
        export_btn = JButton("Export Results")
        export_btn.addActionListener(lambda e: self._export_results())
        
        bottom_panel.add(self.status_label)
        bottom_panel.add(Box.createHorizontalStrut(20))
        bottom_panel.add(self.captures_label)
        bottom_panel.add(Box.createHorizontalStrut(20))
        bottom_panel.add(goto_btn)
        bottom_panel.add(export_btn)
        
        # Add components to main panel
        self.panel.add(query_wrapper, BorderLayout.NORTH)
        self.panel.add(split_pane, BorderLayout.CENTER)
        self.panel.add(bottom_panel, BorderLayout.SOUTH)
        
        # Enable Enter key for search
        self.query_field.addActionListener(lambda e: self._run_query(False))
    
    def getPanel(self):
        return self.panel
    
    def _toggle_debug(self):
        """Toggle debug mode"""
        self.engine.debug = self.debug_checkbox.isSelected()
        print("Debug mode: {}".format(self.engine.debug))
    
    def _run_query(self, search_all):
        """Execute the query"""
        query = self.query_field.getText().strip()
        if not query:
            return
        
        self.status_label.setText("Searching...")
        self.table_model.setRowCount(0)
        self.details_area.setText("")
        
        try:
            # Only search current function
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
                context = result.get('context', '')[:50] + "..." if len(result.get('context', '')) > 50 else result.get('context', '')
                
                row_data = [
                    i + 1,
                    result['function'],
                    result['type'],
                    result['text'][:30] + "..." if len(result['text']) > 30 else result['text'],
                    context,
                    str(result['address']) if result['address'] else "N/A",
                    result.get('parent_type', 'unknown')
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
        """Handle row selection - show details"""
        row = self.results_table.getSelectedRow()
        if row >= 0 and row < len(self.results):
            result = self.results[row]
            
            # Show detailed information
            details = "=== Match Details ===\n"
            details += "Type: {}\n".format(result['type'])
            details += "Text: {}\n".format(result['text'])
            details += "Address: {}\n".format(result['address'])
            details += "Function: {}\n".format(result['function'])
            details += "Parent Type: {}\n".format(result.get('parent_type', 'unknown'))
            
            if result.get('context'):
                details += "\nContext:\n{}\n".format(result['context'])
            
            if result.get('captures'):
                details += "\nCaptures:\n"
                for k, v in result['captures'].items():
                    details += "  {} = {}\n".format(k, v)
            
            if result.get('siblings'):
                details += "\nSiblings:\n"
                for sib in result['siblings']:
                    details += "  {} : {}\n".format(sib['type'], sib['text'])
            
            self.details_area.setText(details)
            
            # Go to address
            if result['address']:
                goTo(result['address'])
    
    def _choose_highlight_color(self):
        """Let user choose highlight color"""
        color = JColorChooser.showDialog(self.panel, "Choose Highlight Color", self.engine.highlight_color)
        if color:
            self.engine.highlight_color = color
    
    def _export_results(self):
        """Export results to file"""
        if not self.results:
            JOptionPane.showMessageDialog(self.panel, "No results to export")
            return
            
        chooser = JFileChooser()
        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            try:
                with open(chooser.getSelectedFile().getAbsolutePath(), 'w') as f:
                    f.write("AST Query Results\n")
                    f.write("Query: {}\n\n".format(self.query_field.getText()))
                    
                    for i, result in enumerate(self.results):
                        f.write("Match #{}\n".format(i + 1))
                        f.write("-" * 40 + "\n")
                        f.write("Type: {}\n".format(result['type']))
                        f.write("Text: {}\n".format(result['text']))
                        f.write("Function: {}\n".format(result['function']))
                        f.write("Address: {}\n".format(result['address']))
                        if result.get('context'):
                            f.write("Context: {}\n".format(result['context']))
                        if result.get('captures'):
                            f.write("Captures: {}\n".format(result['captures']))
                        f.write("\n")
                        
                JOptionPane.showMessageDialog(self.panel, "Results exported successfully")
            except Exception as e:
                JOptionPane.showMessageDialog(self.panel, "Export failed: {}".format(str(e)))

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