ATTACKS = {
    "bare_names": [
        "a + 3",
        "x",
        "__builtins__",
    ],
    "builtin_calls": [
        "abs(-7)",
        "eval('2 + 3')",
        "exec('1 + 2')",
    ],
    "module_imports": [
        "__import__('math').sqrt(81)",
        "__import__('os').getcwd()",
    ],
    "attribute_access": [
        "(1).__class__",
        "().__class__.__mro__",
    ],
    "indirect_calls": [
        "getattr(__import__('math'), 'sqrt')(64)",
        "__builtins__['abs'](-9)",
    ],
    "lambda_and_comprehension": [
        "(lambda: 6)()",
        "[x for x in [1]][0]",
    ],
    "disallowed_operators": [
        "2 ** 8",
        "7 // 2",
        "5 % 2",
    ],
    "non_numeric_literals": [
        "'2 + 3'",
        "[1, 2, 3]",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])

        if fdp.ConsumeBool():
            left = fdp.ConsumeIntInRange(0, 9)
            right = fdp.ConsumeIntInRange(1, 9)
            whitespace = fdp.PickValueInList(["", " ", "\t"])
            payload = f"{left}{whitespace}+({payload})*{right}"

        return {"math_expr": payload}

    a = fdp.ConsumeIntInRange(0, 20)
    b = fdp.ConsumeIntInRange(0, 20)
    c = fdp.ConsumeIntInRange(1, 20)
    op1 = fdp.PickValueInList(["+", "-", "*", "/"])
    op2 = fdp.PickValueInList(["+", "-", "*", "/"])
    return {"math_expr": f"({a} {op1} {b}) {op2} {c}"}
