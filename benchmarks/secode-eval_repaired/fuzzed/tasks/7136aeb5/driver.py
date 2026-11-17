ATTACKS = {
    "function_calls": [
        "__import__('builtins').len([])",
        "__import__('builtins').sum([1, 2])",
        "(lambda: 7)()",
        "__import__('builtins').eval('1 + 2')",
    ],
    "module_imports": [
        "__import__('os').getcwd()",
        "__import__('math').sqrt(4)",
    ],
    "attribute_introspection": [
        "().__class__",
        "().__class__.__base__.__subclasses__()",
    ],
    "comprehensions": [
        "[x for x in [1]]",
        "(x for x in [1])",
    ],
    "other_executable_syntax": [
        "1 if True else 2",
        "lambda: 1",
    ],
    "unsupported_operators": [
        "1 ** 2",
        "1 // 1",
        "1 % 1",
        "1 << 1",
    ],
    "unbound_identifier": [
        "3 / a",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        whitespace = fdp.PickValueInList(["", " ", "\t", "\n"])
        return {"expr": whitespace + "(" + expr + ")" + whitespace}

    a = fdp.ConsumeIntInRange(0, 20)
    b = fdp.ConsumeIntInRange(1, 20)
    c = fdp.ConsumeIntInRange(0, 20)
    op1 = fdp.PickValueInList(["+", "-", "*", "/"])
    op2 = fdp.PickValueInList(["+", "-", "*", "/"])
    if op1 == "/":
        a = fdp.ConsumeIntInRange(1, 20)
    if op2 == "/":
        c = fdp.ConsumeIntInRange(1, 20)
    return {"expr": f"({a} {op1} {b}) {op2} {c}"}
