ATTACKS = {
    "lambda": [
        "lambda x: x + 10",
        "(lambda x: x * x)(3)",
    ],
    "dynamic_import": [
        "__import__('math').sqrt(16)",
        "__import__('os').getcwd()",
    ],
    "builtin_calls": [
        "len([1, 2])",
        "sum((1, 2, 3))",
    ],
    "dunder_attribute_access": [
        "().__class__.__mro__",
        "(1).__class__.__name__",
    ],
    "comprehension": [
        "[x * x for x in (1, 2, 3)]",
    ],
    "assignment_expression": [
        "(x := 3) + x",
    ],
    "conditional_expression": [
        "1 if True else 0",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        code = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            code = "(" + code + ")"
        return {"code_string": code}

    left = fdp.ConsumeIntInRange(0, 20)
    right = fdp.ConsumeIntInRange(0, 20)
    third = fdp.ConsumeIntInRange(0, 10)
    operator = fdp.PickValueInList(["+", "-", "*", "//", "%"])
    return {"code_string": f"{left} {operator} {right} + {third}"}
