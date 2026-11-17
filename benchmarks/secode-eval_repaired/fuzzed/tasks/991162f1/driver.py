ATTACKS = {
    "lambda_expression": [
        "lambda x: x + 10",
        "(lambda x: x * 2)(3)",
    ],
    "function_calls": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').sum([1, 2, 3])",
    ],
    "attribute_access": [
        "(1).__class__",
        "().__class__.__mro__",
    ],
    "comprehensions": [
        "[x * 2 for x in (1, 2, 3)]",
        "{x: x + 1 for x in (1, 2)}",
    ],
    "formatted_strings": [
        "f'{1 + 2}'",
        "f'{__import__(\"math\").sqrt(9)}'",
    ],
    "assignment_expression": [
        "(x := 7)",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        expression = fdp.PickValueInList(ATTACKS[technique])
        wrapper = fdp.PickValueInList(["", " ", "\t", "()"])
        if wrapper == "()":
            expression = "(" + expression + ")"
        else:
            expression = wrapper + expression + wrapper
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(1, 20)
        c = fdp.ConsumeIntInRange(0, 10)
        template = fdp.PickValueInList([
            "{a} + {b} * {c}",
            "({a} - {b}) * {c}",
            "{a} / {b}",
            "{a} ** {c}",
            "-{a} + {b}",
        ])
        expression = template.format(a=a, b=b, c=c)

    return {"math_expression": expression}
