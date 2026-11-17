ATTACKS = {
    "dynamic_code_execution": [
        "exec('print(10)')",
        "eval('6 * 7')",
    ],
    "module_import": [
        "__import__('math').sqrt(16)",
    ],
    "attribute_traversal": [
        "().__class__.__mro__",
        "getattr(1, '__class__')",
    ],
    "callable_expression": [
        "(lambda: 7)()",
    ],
    "comprehension": [
        "[x * x for x in (2, 3)]",
    ],
    "formatted_string": [
        "f'{1 + 2}'",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        expr = (" " * fdp.ConsumeIntInRange(0, 2)) + ("(" * fdp.ConsumeIntInRange(0, 2)) + expr + (")" * fdp.ConsumeIntInRange(0, 2))
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(0, 20)
        c = fdp.ConsumeIntInRange(0, 20)
        if fdp.ConsumeBool():
            expr = f"{a} * ({b} + {c})"
        else:
            expr = f"{a} + {b} - {c}"
    return {"user_expr": expr}
