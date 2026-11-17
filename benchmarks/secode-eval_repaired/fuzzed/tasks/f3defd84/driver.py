ATTACKS = {
    "code_execution": [
        "exec('print(10)')",
        "print(10)",
    ],
    "dynamic_import": [
        "__import__('math').sqrt(16)",
        "__import__('builtins').print(10)",
    ],
    "attribute_traversal": [
        "().__class__.__mro__",
        "().__class__.__base__.__subclasses__()",
        "(1).__class__",
    ],
    "lambda_call": [
        "(lambda: 7)()",
        "(lambda x: x + 1)(4)",
    ],
    "comprehension": [
        "[x for x in (1, 2)]",
        "{x: x * 2 for x in (1, 2)}",
    ],
    "formatted_string": [
        "f'{1 + 2}'",
        "f\"{__import__('builtins').print(10)}\"",
    ],
    "assignment_expression": [
        "(x := 5)",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        expression = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            expression = "(" + expression + ")"
        if fdp.ConsumeBool():
            expression = " " + expression + " "
    else:
        a = fdp.ConsumeIntInRange(0, 20)
        b = fdp.ConsumeIntInRange(1, 20)
        c = fdp.ConsumeIntInRange(0, 20)
        expression = fdp.PickValueInList([
            f"{a} + {b} * {c}",
            f"({a} + {b}) * {c}",
            f"{a} - {b}",
            f"{a} / {b}",
            f"{a} < {b} and {b} <= {c}",
            f"not ({a} == {b})",
        ])
    return {"expression": expression}
