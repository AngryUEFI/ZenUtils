import ast

class ConditionEvaluator:
    """
    Evaluate simple boolean expressions with &&, ||, comparison ops,
    variables and numeric literals (dec, hex, bin). Also extracts all
    equality tests of the form `var == const`.
    """
    # AST node types allowed in expressions
    _ALLOWED_NODES = {
        ast.Expression, ast.BoolOp, ast.UnaryOp, ast.Compare,
        ast.Name, ast.Load, ast.Constant,
        ast.And, ast.Or, ast.Not,
        ast.Gt, ast.Lt, ast.GtE, ast.LtE, ast.Eq, ast.NotEq,
        ast.USub, ast.UAdd
    }

    _ALLOWED_NODES_FOR_EXTRACT = {
        ast.Expression, ast.BoolOp, ast.Compare,
        ast.Name, ast.Load, ast.Constant,
        ast.And, ast.Eq
    }

    def __init__(self, variables):
        """
        variables: dict[str -> obj] where obj.value is the integer value
        """
        # build evaluation namespace: var_name -> integer
        self._env = {name: obj['value'] for name, obj in variables.items()}

    @staticmethod
    def _sanitize(expr):
        # convert && → and, || → or
        return expr.replace('&&', ' and ').replace('||', ' or ')

    @staticmethod
    def _check_node(node):
        if type(node) not in ConditionEvaluator._ALLOWED_NODES:
            raise ValueError(f"Unsupported expression element: {type(node).__name__}")
        for child in ast.iter_child_nodes(node):
            ConditionEvaluator._check_node(child)
    
    @staticmethod
    def _check_node_for_extract(node):
        if type(node) not in ConditionEvaluator._ALLOWED_NODES_FOR_EXTRACT:
            raise ValueError(f"Unsupported expression element: {type(node).__name__}")
        for child in ast.iter_child_nodes(node):
            ConditionEvaluator._check_node_for_extract(child)

    def evaluate(self, expr):
        """
        Parse and evaluate the boolean expression.
        Returns (result: bool)
        """
        src = self._sanitize(expr)
        tree = ast.parse(src, mode='eval')
        # validate AST
        self._check_node(tree)
        # safe evaluation
        code = compile(tree, '<expr>', 'eval')
        result = eval(code, {'__builtins__': None}, self._env)
        return bool(result)

    # For extraction only expr of the form 'var == val [&& var_n == val_n]*' are allowed
    # For extraction each variable may only occur once
    @staticmethod
    def extract_defs_from_condition(expr):
        """
        Parse and extract defs from boolean expression.
        Returns (eq_tests: dict[var_name -> expected_value])
        """
        src = ConditionEvaluator._sanitize(expr)
        tree = ast.parse(src, mode='eval')
        # validate AST
        ConditionEvaluator._check_node_for_extract(tree)
        # extract unique equality tests
        eq_tests = {}
        class EqVisitor(ast.NodeVisitor):
            def visit_Compare(self, node):
                if len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
                    left, right = node.left, node.comparators[0]
                    if isinstance(left, ast.Name) and isinstance(right, ast.Constant):
                        if left.id in eq_tests:
                            raise ValueError(f"Multiple occurences of var: {left.id}")
                        eq_tests[left.id] = right.value
                    elif isinstance(right, ast.Name) and isinstance(left, ast.Constant):
                        if right.id in eq_tests:
                            raise ValueError(f"Multiple occurences of var: {right.id}")
                        eq_tests[right.id] = left.value
                self.generic_visit(node)
        EqVisitor().visit(tree)
        return eq_tests
