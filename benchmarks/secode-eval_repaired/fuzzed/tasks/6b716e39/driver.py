ATTACKS = {
    "builtin_calls": [
        "exec('print(10)')",
        "print(10)",
        "abs(-3)",
    ],
    "import_calls": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').len([1, 2])",
    ],
    "attribute_access": [
        "().__class__",
        "(1).__class__.__mro__",
    ],
    "comprehensions": [
        "[x for x in (1, 2)]",
        "{x: x for x in (1,)}",
    ],
    "lambda_calls": [
        "(lambda: 7)()",
    ],
    "code_compilation": [
        "compile('1+1', '<x>', 'eval')",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
        if fdp.ConsumeBool():
            expr = " " + expr + " "
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(1, 20)
        c = fdp.ConsumeIntInRange(0, 20)
        kind = fdp.ConsumeIntInRange(0, 3)
        if kind == 0:
            expr = f"{a} * ({b} + {c})"
        elif kind == 1:
            expr = f"{a} + {b} - {c}"
        elif kind == 2:
            expr = f"{a} < {b} and {b} <= {c}"
        else:
            expr = f"({a} != {b}) or ({c} == 0)"

    return {"math_expr": expr}
