ATTACKS = {
    "direct_exec": [
        "exec('print(123)')",
        "exec('x=1')",
    ],
    "builtin_import": [
        "__import__('builtins').print(123)",
        "__import__('builtins').exec('print(123)')",
    ],
    "nested_eval": [
        "eval('1+2')",
        "__import__('builtins').eval('1+2')",
    ],
    "callable_expression": [
        "(lambda: 7)()",
        "(lambda x: x+1)(2)",
    ],
    "attribute_introspection": [
        "().__class__",
        "().__class__.__mro__",
    ],
    "comprehension": [
        "[x for x in (1,2)]",
        "{x:x for x in (1,2)}",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
        return {"input_expr": expr}

    a = fdp.ConsumeIntInRange(0, 20)
    b = fdp.ConsumeIntInRange(1, 20)
    op = fdp.PickValueInList(["+", "-", "*", "/", "//", "%", "**"])
    if op == "**":
        b = fdp.ConsumeIntInRange(0, 4)
    return {"input_expr": f"{a} {op} {b}"}
