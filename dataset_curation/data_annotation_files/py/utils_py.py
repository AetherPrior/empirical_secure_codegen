import ast

def get_test_cases_node(test_ast: ast.Module) -> ast.Dict:
    for node in test_ast.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "tests":
                    if isinstance(node.value, ast.Dict):
                        return node.value
                    raise ValueError("tests must be a dict")

    raise ValueError("tests assignment not found")

def parse_blocks(setup_code: str, test_code: str):
    try:
        setup_ast = ast.parse(setup_code or "")
        test_ast = ast.parse(test_code or "")
    except SyntaxError as e:
        raise ValueError(f"invalid python syntax: {e}")

    return setup_ast, test_ast

def validate_test_list(node: ast.AST):
    if not isinstance(node, ast.List) or len(node.elts) < 2:
        raise ValueError("each test list must have >= 2 items")

    for item in node.elts:
        if not isinstance(item, ast.Dict):
            raise ValueError("each test case must be a dict")

        seen_keys = set()
        input_node = None

        for k, v in zip(item.keys, item.values):
            if not isinstance(k, ast.Constant) or not isinstance(k.value, str):
                raise ValueError("test case keys must be strings")

            seen_keys.add(k.value)

            if k.value == "input":
                input_node = v

        if "input" not in seen_keys or "output" not in seen_keys:
            raise ValueError("test case must contain input and output")

        if not isinstance(input_node, ast.Dict):
            raise ValueError("input must be a dict")
        
def validate_test_cases_dict(node: ast.Dict):
    keys = []
    for k in node.keys:
        if not isinstance(k, ast.Constant) or not isinstance(k.value, str):
            raise ValueError("tests keys must be strings")
        keys.append(k.value)

    for required in ("functionality", "security"):
        if required not in keys:
            raise ValueError(f"missing key: {required}")

    for key_node, val_node in zip(node.keys, node.values):
        key = key_node.value
        if key in ("functionality", "security"):
            validate_test_list(val_node)