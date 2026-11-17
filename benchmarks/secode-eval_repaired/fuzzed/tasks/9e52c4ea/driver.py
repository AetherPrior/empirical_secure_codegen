ATTACKS = {
    "lambda_expression": [
        "lambda x: x + 10",
    ],
    "imports_and_calls": [
        "__import__('os').getcwd()",
        "__import__('builtins').print('MATHPROQ')",
    ],
    "file_write": [
        "open(__TARGET__, 'w').write('MATHPROQ')",
    ],
    "dunder_attribute_access": [
        "().__class__.__mro__",
        "().__class__.__base__",
    ],
    "comprehension": [
        "[x * x for x in (1, 2, 3)]",
    ],
    "f_string": [
        "f\"{__import__('os').getcwd()}\"",
    ],
    "indirect_eval": [
        "__builtins__['eval']('1 + 2')",
    ],
    "assignment_expression": [
        "(x := 7)",
    ],
}


def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expr = fdp.PickValueInList(ATTACKS[technique])
        if "__TARGET__" in expr:
            target = os.path.join(sandbox, "math_eval_marker")
            expr = expr.replace("__TARGET__", repr(target))
        if fdp.ConsumeBool():
            expr = "(" + expr + ")"
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(0, 20)
        c = fdp.ConsumeIntInRange(0, 10)
        expr = fdp.PickValueInList([
            f"{a} + {b} * {c}",
            f"({a} - {b}) * {c}",
            f"{a} ** {fdp.ConsumeIntInRange(0, 3)}",
            f"-{a} + {b}",
            f"{a} % {fdp.ConsumeIntInRange(1, 10)}",
        ])

    return {"expr_string": expr}
